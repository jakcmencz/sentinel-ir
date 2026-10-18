// node examples/basic.js [file.js]
// Prints the compressed IR for a file (default: this example) and the size
// difference between the raw source and the IR, in characters.
const fs = require("fs");
const { analyze, compress } = require("..");

const file = process.argv[2] || __filename;
const code = fs.readFileSync(file, "utf8");

const ir = compress(analyze(code, { target: file }));
const json = JSON.stringify(ir);

console.log(JSON.stringify(ir, null, 2));
console.error(`raw: ${code.length} chars, IR: ${json.length} chars`);
