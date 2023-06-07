// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {Diagnostic, DiagnosticSeverity} from 'vscode';
import {DockerfileParser} from 'dockerfile-ast';
import * as rm from 'typed-rest-client/RestClient';
import * as httpm from 'typed-rest-client/HttpClient';
import Docker = require('dockerode');

let imageRegex = new RegExp('[q|Q][u|U][a|A][y|Y]\\.[i|I][o|O]\\/([^\\/.]+\\/)?[^\\/.]+(:.+)?');
let digestRegex = new RegExp('Digest: sha256:[A-Fa-f0-9{64}]');

let baseUrl: string = 'https://quay.io';
let restc: rm.RestClient = new rm.RestClient('crda', baseUrl);

let severities: string[] = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];

interface PullStatus {
    status: string
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

        const docker = new Docker();
        let diagnostics: Diagnostic[] = [];
        for (let from of froms) {
            let image = from.getImage();
            console.log(image);
            if (image && imageRegex.test(image)) {
                try {
                    const pullStream = await docker.pull(image);
                    await new Promise(resolve => docker.modem.followProgress(pullStream, (error, result) => {
                        if (error) {
                            resolve(error);
                        } else {
                            resolve(result);
                        }
                    })).then(async result => {
                        if (isError(result)) {
                            console.log(result);
                            let range = from.getImageRange();
                            diagnostics.push({
                                code: '',
                                message: (<Error>result).message,
                                range: new vscode.Range(
                                    new vscode.Position(range?.start.line!, range?.start.character!), new vscode.Position(range?.end.line!, range?.end.character!),
                                ),
                                severity: vscode.DiagnosticSeverity.Error,
                                source: '',
                                relatedInformation: []
                            });
                        } else {
                            console.log(result);
                            let results = result as object[];
                            for (let status of results) {
                                let s = status as PullStatus;
                                if (digestRegex.test(s.status)) {
                                    await getImageManifestAddress(image!, s.status).then(
                                        async result => {
                                            if (result[0] === null || result[1] === null) {
                                                return;
                                            }

                                            let range = from.getImageRange();
                                            diagnostics.push({
                                                code: '',
                                                message: result[0],
                                                range: new vscode.Range(new vscode.Position(range?.start.line!, range?.start.character!),
                                                    new vscode.Position(range?.end.line!, range?.end.character!),),
                                                severity: result[1],
                                                source: '',
                                                relatedInformation: []
                                            });
                                        }
                                    );
                                    break;
                                }
                            }
                        }
                    });
                } catch (error) {
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

async function getImageManifestAddress(image: string, digest: string): Promise<[string, DiagnosticSeverity]> {
    let repo = image.slice(8, image.lastIndexOf(":"));
    let sha = digest.slice(8);
    let path = '/api/v1/repository/' + repo + '/manifest/' + sha + '/security';
    let options: rm.IRequestOptions = <rm.IRequestOptions>{
        queryParameters: {
            params: {
                vulnerabilities: 'true',
            }
        }
    };
    try {
        let restRes: rm.IRestResponse<Vulnerabilities> = await restc.get<Vulnerabilities>(path, options);
        if (restRes.statusCode === httpm.HttpCodes.NotFound) {
            return ["Status Code 404 - Request to quay.io failed", vscode.DiagnosticSeverity.Error];
        }

        let vulMap = new Map<string, string>();
        for (let feature of restRes.result.data.Layer.Features) {
            for (let vul of feature.Vulnerabilities) {
                vulMap.set(vul.Name, vul.Severity);
            }
        }

        if (vulMap.size === 0) {
            return [null, null];
        }

        let message: string = "";
        for (let severity of severities) {
            for (let [n, s] of vulMap) {
                if (s === severity) {
                    message += (n + ": " + s + "\n");
                }
            }
        }

        let severity: DiagnosticSeverity = DiagnosticSeverity.Warning;
        for (let [n, s] of vulMap) {
            if (s === "Critical" || s=== "High") {
                severity = DiagnosticSeverity.Error;
            }
        }

        return [message, severity];
    } catch (error) {
        return ["Status Code " + error['statusCode'] + " - " + error.message + ", Result: " + error['result'], vscode.DiagnosticSeverity.Error];
    }
}

const isError = (err: unknown): err is Error => err instanceof Error;
