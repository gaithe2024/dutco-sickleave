// Usage: node dha_test.js <barcode> <pin>
const { dhaVerify } = require("./dha");
dhaVerify(process.argv[2] || "1234567890", process.argv[3] || "1234").then((r) => console.log("DHA_RESULT", JSON.stringify(r).slice(0, 600)));
