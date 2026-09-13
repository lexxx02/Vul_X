import Parser from 'tree-sitter';
import JavaScript from 'tree-sitter-javascript';

const parser = new Parser();
parser.setLanguage(JavaScript);

const sourceCode = 'const saludo = "Hola VulX"; console.log(saludo);';
const tree = parser.parse(sourceCode);

console.log("✅ AST generado con éxito.");
console.log("Tipo de nodo raíz:", tree.rootNode.type);
console.log("Cantidad de nodos hijos:", tree.rootNode.childCount);