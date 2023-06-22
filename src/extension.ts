// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {Diagnostic, DiagnosticSeverity} from 'vscode';
import {DockerfileParser} from 'dockerfile-ast';
import * as rm from 'typed-rest-client/RestClient';
import * as httpm from 'typed-rest-client/HttpClient';
import Docker = require('dockerode');

let imageRegex = new RegExp('^(?<Name>(?<=^)(?:(?<Domain>(?:(?:localhost|[\\w-]+(?:\\.[\\w-]+)+)(?::\\d+)?)|[\\w]+:\\d+)\\/)?\\/?(?<Namespace>(?:(?:[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*)\\/)*)(?<Repo>[a-z0-9-]+))[:@]?(?<Reference>(?<=:)(?<Tag>[\\w][\\w.-]{0,127})|(?<=@)(?<Digest>[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][0-9A-Fa-f]{32,}))?');

let baseUrl: string = 'https://quay.io';
let restc: rm.RestClient = new rm.RestClient('crda', baseUrl);

let baseUrl2: string = 'http://localhost:8080';
let restc2: rm.RestClient = new rm.RestClient('crda', baseUrl2);

let severities: string[] = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
let severityColors = new Map<string, string>([
    ["Critical", "color: rgb(214, 68, 86)"],
    ["High", "color: rgb(247, 116, 84)"],
    ["Medium", "color: rgb(252, 166, 87)"],
    ["Low", "color: rgb(248, 202, 28)"],
    ["Unknown", "color: rgb(155, 155, 155)"],
]);

interface ManifestPayload {
    digest: string,
    is_manifest_list: boolean,
    manifest_data: string,
}

interface Platform {
    "architecture": string,
    "os": string,
}

interface ManifestData {
    mediaType: string,
    manifests: Manifest[],
}

interface Manifest {
    "digest": string,
    "platform": Platform,
}

interface Vulnerability {
    Name: string,
    Severity: string,
    Link: string,
}

interface Feature {
    Name: string,
    Vulnerabilities: Vulnerability[],
}

interface Layer {
    Name: string,
    Features: Feature[],
}

interface Data {
    Layer: Layer,
}

interface SecurityPayload {
    status: string,
    data: Data,
}

interface Image2 {
    ref: string,
    vulnerabilities: Vulnerability2[],
}

interface Vulnerability2 {
    id: string;
    severity: string;
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
            if (image && imageRegex.test(image) && image.slice(0, 8).toLowerCase() === "quay.io/") {
                try {
                    // let [digests, arch, os] = await getImageDigest(image);
                    // if (digests === undefined) {
                    //     continue;
                    // }
                    //
                    // let [repo, digest] = await getImageManifestRef(digests, arch, os);
                    // if (repo === undefined || digest === undefined) {
                    //     continue;
                    // }

                    let [vulnerability, message, severity] = await getImageVulnerabilities2(image);
                    if (vulnerability !== undefined && message !== undefined) {
                        let messageSeverity: DiagnosticSeverity;
                        if (severity === "Critical" || severity === "High") {
                            messageSeverity = DiagnosticSeverity.Error;
                        } else if (severity !== undefined) {
                            messageSeverity = DiagnosticSeverity.Warning;
                        } else {
                            messageSeverity = DiagnosticSeverity.Information;
                        }

                        let range = from.getImageRange();
                        diagnostics.push({
                            code: vulnerability,
                            message: message,
                            range: new vscode.Range(new vscode.Position(range?.start.line!, range?.start.character!),
                                new vscode.Position(range?.end.line!, range?.end.character!),),
                            severity: messageSeverity,
                            source: '',
                            relatedInformation: [],
                        });
                    }
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

async function getImageVulnerabilities(image: string, repository: string, digest: string): Promise<[string, string, string]> {
    let path = '/api/v1/repository/' + repository + '/manifest/' + digest + '/security';
    let options: rm.IRequestOptions = <rm.IRequestOptions>{
        queryParameters: {
            params: {
                vulnerabilities: 'true',
            }
        }
    };

    let restRes: rm.IRestResponse<SecurityPayload> = await restc.get<SecurityPayload>(path, options);
    if (restRes.statusCode === httpm.HttpCodes.NotFound) {
        throw Error("Status Code 404 - Request to quay.io failed");
    }

    let vulMap = new Map<string, Vulnerability>();
    for (let feature of restRes.result.data.Layer.Features) {
        for (let vul of feature.Vulnerabilities) {
            vulMap.set(vul.Name, vul);
        }
    }

    if (vulMap.size === 0) {
        return [undefined, undefined, undefined];
    }

    // let severitySet = new Set<string>();
    // let message: string = "";
    // for (let severity of severities) {
    //     for (let [n, v] of vulMap) {
    //         if (v.Severity === severity) {
    //             severitySet.add(v.Severity);
    //             message += n + ": " + v.Severity;
    //             if (v.Link !== undefined && v.Link.length > 0) {
    //                 message += ": " + v.Link + "\n";
    //             } else {
    //                 message += "\n";
    //             }
    //         }
    //     }
    // }

    let severityMap = new Map<string, number>();
    for (let severity of severities) {
        severityMap.set(severity, 0);
    }

    let vulnerability: string;
    for (let [n, v] of vulMap) {
        severityMap.set(v.Severity, severityMap.get(v.Severity) + 1);
        if (vulnerability === undefined) {
            vulnerability = n;
        }
    }

    let message: string = "Image: " + image + "\n";
    for (let severity of severities) {
        let num = severityMap.get(severity);
        if (num > 0) {
            message += severity + ": " + num + "\n";
        }
    }

    for (let severity of severities) {
        if (severityMap.get(severity) > 0) {
            return [vulnerability, message, severity];
        }
    }

    return [undefined, message, undefined];
}

async function getImageVulnerabilities2(image: string): Promise<[string, string, string]> {
    let path = '/image/vulnerabilities';
    let options: rm.IRequestOptions = <rm.IRequestOptions>{
        queryParameters: {
            params: {
                image: image,
            }
        }
    };

    let restRes: rm.IRestResponse<Image2> = await restc2.get<Image2>(path, options);
    if (restRes.statusCode !== httpm.HttpCodes.OK) {
        throw Error("Status Code " + restRes.statusCode + " - Request to backend failed");
    }

    let vulMap = new Map<string, Vulnerability2>();
    for (let vul of restRes.result.vulnerabilities) {
        vulMap.set(vul.id, vul);
    }

    if (vulMap.size === 0) {
        return [undefined, undefined, undefined];
    }

    let severityMap = new Map<string, number>();
    for (let severity of severities) {
        severityMap.set(severity, 0);
    }

    let vulnerability: string;
    for (let [n, v] of vulMap) {
        severityMap.set(v.severity, severityMap.get(v.severity) + 1);
        if (vulnerability === undefined) {
            vulnerability = n;
        }
    }

    let message: string = "Image: " + image + "\n";
    for (let severity of severities) {
        let num = severityMap.get(severity);
        if (num > 0) {
            message += severity + ": " + num + "\n";
        }
    }

    for (let severity of severities) {
        if (severityMap.get(severity) > 0) {
            return [vulnerability, message, severity];
        }
    }

    return [undefined, message, undefined];
}

async function getImageDigest(imgName: string): Promise<[string[], string, string]> {
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
    return [info.RepoDigests, info.Architecture, info.Os];
}

async function getImageManifestRef(digests: string[], arch: string, os: string): Promise<[string, string]> {
    let imageRepository: string;
    let manifestRepository: string;
    let manifests: string;
    let manifestRef: string;
    for (let digest of digests) {
        let at = digest.indexOf("@");
        let repo = digest.slice(8, at);
        let ref = digest.slice(at + 1);
        let path = '/api/v1/repository/' + repo + '/manifest/' + ref;
        let restRes: rm.IRestResponse<ManifestPayload> = await restc.get<ManifestPayload>(path);
        if (restRes.statusCode !== httpm.HttpCodes.NotFound) {
            if (restRes.result.is_manifest_list) {
                imageRepository = repo;
                manifests = restRes.result.manifest_data;
            } else {
                manifestRepository = repo;
                manifestRef = restRes.result.digest;
            }
        }
    }

    if (manifestRepository !== undefined && manifestRef !== undefined) {
        return [manifestRepository, manifestRef];
    }

    console.log(process.arch);

    if (imageRepository !== undefined && manifests !== undefined) {
        let manifestData: ManifestData = JSON.parse(manifests);
        for (let manifest of manifestData.manifests) {
            if (os === manifest.platform.os && arch === manifest.platform.architecture) {
                return [imageRepository, manifest.digest];
            }
        }
    }

    return [undefined, undefined];
}

const isError = (err: unknown): err is Error => err instanceof Error;
