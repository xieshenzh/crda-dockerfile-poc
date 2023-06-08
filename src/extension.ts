// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {Diagnostic, DiagnosticSeverity} from 'vscode';
import {DockerfileParser} from 'dockerfile-ast';
import * as rm from 'typed-rest-client/RestClient';
import * as httpm from 'typed-rest-client/HttpClient';
import Docker = require('dockerode');

let imageRegex = new RegExp('[q|Q][u|U][a|A][y|Y]\\.[i|I][o|O]\\/([^\\/.]+\\/)?[^\\/.]+(:.+)?'); //todo
let digestRegex = new RegExp('Digest: sha256:[A-Fa-f0-9{64}]');

let baseUrl: string = 'https://quay.io';
let restc: rm.RestClient = new rm.RestClient('crda', baseUrl);

let severities: string[] = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];

interface PullStatus {
    status: string
}

interface Manifest {
    digest: string,
    is_manifest_list: boolean,
    manifest_data: string
}

interface Vulnerability {
    Name: string,
    Severity: string,
}

interface Feature {
    Name: string,
    Vulnerabilities: Vulnerability[]
}

interface Layer {
    Name: string,
    Features: Feature[]
}

interface Data {
    Layer: Layer
}

interface Vulnerabilities {
    status: string,
    data: Data
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('dockerfile');

    context.subscriptions.push(diagnosticCollection);

    if (vscode.window.activeTextEditor) {
        updateDiagnostics(vscode.window.activeTextEditor.document).then(diagnostics => {
            if (diagnostics === undefined || diagnostics.length === 0) {
                diagnosticCollection.clear();
            } else {
                diagnosticCollection.set(vscode.window.activeTextEditor!.document.uri, diagnostics);
            }
        });
    }
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                updateDiagnostics(editor.document).then(diagnostics => {
                    if (diagnostics === undefined || diagnostics.length === 0) {
                        diagnosticCollection.clear();
                    } else {
                        diagnosticCollection.set(editor.document.uri, diagnostics);
                    }
                });
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => updateDiagnostics(e.document).then(diagnostics => {
            if (diagnostics === undefined || diagnostics.length === 0) {
                diagnosticCollection.clear();
            } else {
                diagnosticCollection.set(e.document.uri, diagnostics);
            }
        }))
    );

    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument(doc => diagnosticCollection.delete(doc.uri))
    );
}

// This method is called when your extension is deactivated
export function deactivate() {
}

async function updateDiagnostics(document: vscode.TextDocument): Promise<Diagnostic[]> {
    if (document.languageId === "dockerfile") {
        let dockerfile = DockerfileParser.parse(document.getText());
        let froms = dockerfile.getFROMs();

        let diagnostics: Diagnostic[] = [];
        for (let from of froms) {
            let image = from.getImage();
            console.log(image);
            if (image && imageRegex.test(image)) {
                try {
                    let digests = await getImageDigest(image);
                    let [repo, digest] = await getImageManifestRef(digests);
                    let [message, severity] = await getImageVulnerabilities(repo, digest);

                    let messageSeverity: DiagnosticSeverity;
                    if (severity === "Critical" || severity === "High") {
                        messageSeverity = DiagnosticSeverity.Error;
                    } else if (severity !== undefined) {
                        messageSeverity = DiagnosticSeverity.Warning;
                    }

                    let range = from.getImageRange();
                    diagnostics.push({
                        code: '',
                        message: message,
                        range: new vscode.Range(new vscode.Position(range?.start.line!, range?.start.character!),
                            new vscode.Position(range?.end.line!, range?.end.character!),),
                        severity: messageSeverity,
                        source: '',
                        relatedInformation: []
                    });
                } catch
                    (error) {
                    console.error(error);
                    let range = from.getImageRange();
                    diagnostics.push({
                        code: '',
                        message: error!.toString(),
                        range: new vscode.Range(
                            new vscode.Position(range?.start.line!, range?.start.character!), new vscode.Position(range?.end.line!, range?.end.character!),
                        ),
                        severity: vscode.DiagnosticSeverity.Error,
                        source: '',
                        relatedInformation: []
                    });
                }
            }
        }
        return diagnostics;
    } else {
        return [] as Diagnostic[];
    }
}

async function getImageVulnerabilities(repository: string, digest: string): Promise<[string, string]> {
    let path = '/api/v1/repository/' + repository + '/manifest/' + digest + '/security';
    let options: rm.IRequestOptions = <rm.IRequestOptions>{
        queryParameters: {
            params: {
                vulnerabilities: 'true',
            }
        }
    };

    let restRes: rm.IRestResponse<Vulnerabilities> = await restc.get<Vulnerabilities>(path, options);
    if (restRes.statusCode === httpm.HttpCodes.NotFound) {
        return ["Status Code 404 - Request to quay.io failed", "Critical"];
    }

    let vulMap = new Map<string, string>();
    for (let feature of restRes.result.data.Layer.Features) {
        for (let vul of feature.Vulnerabilities) {
            vulMap.set(vul.Name, vul.Severity);
        }
    }

    if (vulMap.size === 0) {
        return [undefined, undefined];
    }

    let severitySet = new Set<string>();
    let message: string = "";
    for (let severity of severities) {
        for (let [n, s] of vulMap) {
            if (s === severity) {
                severitySet.add(s);
                message += (n + ": " + s + "\n");
            }
        }
    }

    for (let severity of severities) {
        if (severitySet.has(severity)) {
            return [message, severity];
        }
    }

    return [message, undefined];
}

async function getImageDigest(imgName: string): Promise<string[]> {
    let docker = new Docker();
    let pullStream = await docker.pull(imgName);
    await new Promise(resolve => docker.modem.followProgress(pullStream, (error, result) => {
        if (error) {
            resolve(error);
        } else {
            resolve(result);
        }
    })).then(async result => {
        if (isError(result)) {
            console.log(result);
            throw result;
        } else {
            console.log(result);
        }
    });

    let image = docker.getImage(imgName);
    let info = await image.inspect();
    return info.RepoDigests;
}

async function getImageManifestRef(digests: string[]): Promise<[string, string]> {
    let repository: string;
    let manifestData: string;
    let manifestRef: string;
    for (let digest of digests) {
        let at = digest.indexOf("@");
        let repo = digest.slice(8, at);
        let ref = digest.slice(at + 1);
        let path = '/api/v1/repository/' + repo + '/manifest/' + ref;
        let restRes: rm.IRestResponse<Manifest> = await restc.get<Manifest>(path);
        if (restRes.statusCode !== httpm.HttpCodes.NotFound) {
            repository = repo;
            if (restRes.result.is_manifest_list) {
                manifestData = restRes.result.manifest_data;
            } else {
                manifestRef = restRes.result.digest;
            }
        }
    }

    if (repository !== undefined && manifestRef !== undefined) {
        return [repository, manifestRef];
    }

    //todo
}


const isError = (err: unknown): err is Error => err instanceof Error;
