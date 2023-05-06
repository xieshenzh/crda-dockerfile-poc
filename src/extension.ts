// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {Diagnostic} from 'vscode';
import {DockerfileParser} from 'dockerfile-ast';
import Docker = require('dockerode');

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
            if (image) {
                try {
                    const pullStream = await docker.pull(image);
                    await new Promise(resolve => docker.modem.followProgress(pullStream, (error, result) => {
                        if (error) {
                            resolve(error);
                        } else {
                            resolve(result);
                        }
                    })).then(result => {
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
                            let range = from.getImageRange();
                            diagnostics.push({
                                code: '',
                                message: 'Image with vulnerabilities',
                                range: new vscode.Range(
                                    new vscode.Position(range?.start.line!, range?.start.character!), new vscode.Position(range?.end.line!, range?.end.character!),
                                ),
                                severity: vscode.DiagnosticSeverity.Error,
                                source: '',
                                relatedInformation: []
                            });
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

const isError = (err: unknown): err is Error => err instanceof Error;
