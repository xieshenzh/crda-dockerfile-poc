// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {DockerfileParser} from 'dockerfile-ast';
import {Diagnostic} from "vscode";

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('dockerfile');

    context.subscriptions.push(diagnosticCollection);

    if (vscode.window.activeTextEditor) {
        updateDiagnostics(vscode.window.activeTextEditor.document, diagnosticCollection);
    }
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                updateDiagnostics(editor.document, diagnosticCollection);
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => updateDiagnostics(e.document, diagnosticCollection))
    );

    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument(doc => diagnosticCollection.delete(doc.uri))
    );
}

// This method is called when your extension is deactivated
export function deactivate() {
}

function updateDiagnostics(document: vscode.TextDocument, collection: vscode.DiagnosticCollection): void {
    if (document.languageId === "dockerfile") {
        let dockerfile = DockerfileParser.parse(document.getText());

        let froms = dockerfile.getFROMs();

        let diagnostics : Diagnostic[] = [];
        for (let from of froms) {
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

        collection.set(document.uri, diagnostics);
    } else {
        collection.clear();
    }
}
