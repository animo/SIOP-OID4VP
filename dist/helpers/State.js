"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createState = exports.getState = exports.toNonce = exports.getNonce = void 0;
const sha_js_1 = __importDefault(require("sha.js"));
const uuid_1 = require("uuid");
const Encodings_1 = require("./Encodings");
function getNonce(state, nonce) {
    return nonce || toNonce(state);
}
exports.getNonce = getNonce;
function toNonce(input) {
    const buff = (0, sha_js_1.default)('sha256').update(input).digest();
    return (0, Encodings_1.base64urlEncodeBuffer)(buff);
}
exports.toNonce = toNonce;
function getState(state) {
    return state || createState();
}
exports.getState = getState;
function createState() {
    return (0, uuid_1.v4)();
}
exports.createState = createState;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiU3RhdGUuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvaGVscGVycy9TdGF0ZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxvREFBeUI7QUFDekIsK0JBQW9DO0FBRXBDLDJDQUFvRDtBQUVwRCxTQUFnQixRQUFRLENBQUMsS0FBYSxFQUFFLEtBQWM7SUFDcEQsT0FBTyxLQUFLLElBQUksT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBQ2pDLENBQUM7QUFGRCw0QkFFQztBQUVELFNBQWdCLE9BQU8sQ0FBQyxLQUFhO0lBQ25DLE1BQU0sSUFBSSxHQUFHLElBQUEsZ0JBQUcsRUFBQyxRQUFRLENBQUMsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsTUFBTSxFQUFFLENBQUM7SUFDbEQsT0FBTyxJQUFBLGlDQUFxQixFQUFDLElBQUksQ0FBQyxDQUFDO0FBQ3JDLENBQUM7QUFIRCwwQkFHQztBQUVELFNBQWdCLFFBQVEsQ0FBQyxLQUFjO0lBQ3JDLE9BQU8sS0FBSyxJQUFJLFdBQVcsRUFBRSxDQUFDO0FBQ2hDLENBQUM7QUFGRCw0QkFFQztBQUVELFNBQWdCLFdBQVc7SUFDekIsT0FBTyxJQUFBLFNBQU0sR0FBRSxDQUFDO0FBQ2xCLENBQUM7QUFGRCxrQ0FFQyJ9