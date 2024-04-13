"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationResponse = void 0;
const authorization_request_1 = require("../authorization-request");
const Opts_1 = require("../authorization-request/Opts");
const id_token_1 = require("../id-token");
const types_1 = require("../types");
const OpenID4VP_1 = require("./OpenID4VP");
const Opts_2 = require("./Opts");
const Payload_1 = require("./Payload");
class AuthorizationResponse {
    constructor({ authorizationResponsePayload, idToken, responseOpts, authorizationRequest, }) {
        this._authorizationRequest = authorizationRequest;
        this._options = responseOpts;
        this._idToken = idToken;
        this._payload = authorizationResponsePayload;
    }
    /**
     * Creates a SIOP Response Object
     *
     * @param requestObject
     * @param responseOpts
     * @param verifyOpts
     */
    static fromRequestObject(requestObject, responseOpts, verifyOpts) {
        return __awaiter(this, void 0, void 0, function* () {
            (0, Opts_1.assertValidVerifyAuthorizationRequestOpts)(verifyOpts);
            yield (0, Opts_2.assertValidResponseOpts)(responseOpts);
            if (!requestObject || !requestObject.startsWith('ey')) {
                throw new Error(types_1.SIOPErrors.NO_JWT);
            }
            const authorizationRequest = yield authorization_request_1.AuthorizationRequest.fromUriOrJwt(requestObject);
            return AuthorizationResponse.fromAuthorizationRequest(authorizationRequest, responseOpts, verifyOpts);
        });
    }
    static fromPayload(authorizationResponsePayload, responseOpts) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!authorizationResponsePayload) {
                throw new Error(types_1.SIOPErrors.NO_RESPONSE);
            }
            if (responseOpts) {
                yield (0, Opts_2.assertValidResponseOpts)(responseOpts);
            }
            const idToken = authorizationResponsePayload.id_token ? yield id_token_1.IDToken.fromIDToken(authorizationResponsePayload.id_token) : undefined;
            return new AuthorizationResponse({
                authorizationResponsePayload,
                idToken,
                responseOpts,
            });
        });
    }
    static fromAuthorizationRequest(authorizationRequest, responseOpts, verifyOpts) {
        return __awaiter(this, void 0, void 0, function* () {
            yield (0, Opts_2.assertValidResponseOpts)(responseOpts);
            if (!authorizationRequest) {
                throw new Error(types_1.SIOPErrors.NO_REQUEST);
            }
            const verifiedRequest = yield authorizationRequest.verify(verifyOpts);
            return yield AuthorizationResponse.fromVerifiedAuthorizationRequest(verifiedRequest, responseOpts, verifyOpts);
        });
    }
    static fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, responseOpts, verifyOpts) {
        return __awaiter(this, void 0, void 0, function* () {
            yield (0, Opts_2.assertValidResponseOpts)(responseOpts);
            if (!verifiedAuthorizationRequest) {
                throw new Error(types_1.SIOPErrors.NO_REQUEST);
            }
            const authorizationRequest = verifiedAuthorizationRequest.authorizationRequest;
            // const merged = verifiedAuthorizationRequest.authorizationRequest.requestObject, verifiedAuthorizationRequest.requestObject);
            // const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(merged, await authorizationRequest.getSupportedVersion());
            const presentationDefinitions = JSON.parse(JSON.stringify(verifiedAuthorizationRequest.presentationDefinitions));
            const wantsIdToken = yield authorizationRequest.containsResponseType(types_1.ResponseType.ID_TOKEN);
            const hasVpToken = yield authorizationRequest.containsResponseType(types_1.ResponseType.VP_TOKEN);
            const idToken = wantsIdToken ? yield id_token_1.IDToken.fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, responseOpts) : undefined;
            const idTokenPayload = idToken ? yield idToken.payload() : undefined;
            const authorizationResponsePayload = yield (0, Payload_1.createResponsePayload)(authorizationRequest, responseOpts, idTokenPayload);
            const response = new AuthorizationResponse({
                authorizationResponsePayload,
                idToken,
                responseOpts,
                authorizationRequest,
            });
            if (hasVpToken) {
                const wrappedPresentations = yield (0, OpenID4VP_1.extractPresentationsFromAuthorizationResponse)(response, {
                    hasher: verifyOpts.hasher,
                });
                yield (0, OpenID4VP_1.assertValidVerifiablePresentations)({
                    presentationDefinitions,
                    presentations: wrappedPresentations,
                    verificationCallback: verifyOpts.verification.presentationVerificationCallback,
                    opts: Object.assign(Object.assign({}, responseOpts.presentationExchange), { hasher: verifyOpts.hasher }),
                });
            }
            return response;
        });
    }
    verify(verifyOpts) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b;
            // Merge payloads checks for inconsistencies in properties which are present in both the auth request and request object
            const merged = yield this.mergedPayloads({
                consistencyCheck: true,
                hasher: verifyOpts.hasher,
            });
            if (verifyOpts.state && merged.state !== verifyOpts.state) {
                throw Error(types_1.SIOPErrors.BAD_STATE);
            }
            const verifiedIdToken = yield ((_a = this.idToken) === null || _a === void 0 ? void 0 : _a.verify(verifyOpts));
            const oid4vp = yield (0, OpenID4VP_1.verifyPresentations)(this, verifyOpts);
            // Gather all nonces
            const allNonces = new Set();
            if (oid4vp)
                allNonces.add(oid4vp.nonce);
            if (verifiedIdToken)
                allNonces.add(verifiedIdToken.payload.nonce);
            if (merged.nonce)
                allNonces.add(merged.nonce);
            const firstNonce = Array.from(allNonces)[0];
            if (allNonces.size !== 1 || typeof firstNonce !== 'string') {
                throw new Error('both id token and VPs in vp token if present must have a nonce, and all nonces must be the same');
            }
            if (verifyOpts.nonce && firstNonce !== verifyOpts.nonce) {
                throw Error(types_1.SIOPErrors.BAD_NONCE);
            }
            const state = (_b = merged.state) !== null && _b !== void 0 ? _b : verifiedIdToken === null || verifiedIdToken === void 0 ? void 0 : verifiedIdToken.payload.state;
            if (!state) {
                throw Error('State is required');
            }
            return Object.assign(Object.assign({ authorizationResponse: this, verifyOpts, nonce: firstNonce, state, correlationId: verifyOpts.correlationId }, (this.idToken && { idToken: verifiedIdToken })), (oid4vp && { oid4vpSubmission: oid4vp }));
        });
    }
    get authorizationRequest() {
        return this._authorizationRequest;
    }
    get payload() {
        return this._payload;
    }
    get options() {
        return this._options;
    }
    get idToken() {
        return this._idToken;
    }
    getMergedProperty(key, opts) {
        return __awaiter(this, void 0, void 0, function* () {
            const merged = yield this.mergedPayloads(opts);
            return merged[key];
        });
    }
    mergedPayloads(opts) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b;
            let nonce = this._payload.nonce;
            if ((_a = this._payload) === null || _a === void 0 ? void 0 : _a.vp_token) {
                const presentations = yield (0, OpenID4VP_1.extractPresentationsFromAuthorizationResponse)(this, opts);
                // We do not verify them, as that is done elsewhere. So we simply can take the first nonce
                if (!nonce) {
                    nonce = presentations[0].decoded.nonce;
                }
            }
            const idTokenPayload = yield ((_b = this.idToken) === null || _b === void 0 ? void 0 : _b.payload());
            if ((opts === null || opts === void 0 ? void 0 : opts.consistencyCheck) !== false && idTokenPayload) {
                Object.entries(idTokenPayload).forEach((entry) => {
                    if (typeof entry[0] === 'string' && this.payload[entry[0]] && this.payload[entry[0]] !== entry[1]) {
                        throw Error(`Mismatch in Authorization Request and Request object value for ${entry[0]}`);
                    }
                });
            }
            if (!nonce && this._idToken) {
                nonce = (yield this._idToken.payload()).nonce;
            }
            return Object.assign(Object.assign(Object.assign({}, this.payload), idTokenPayload), { nonce });
        });
    }
}
exports.AuthorizationResponse = AuthorizationResponse;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQXV0aG9yaXphdGlvblJlc3BvbnNlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2F1dGhvcml6YXRpb24tcmVzcG9uc2UvQXV0aG9yaXphdGlvblJlc3BvbnNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7OztBQUVBLG9FQUFnRztBQUNoRyx3REFBMEY7QUFDMUYsMENBQXNDO0FBQ3RDLG9DQUErSTtBQUUvSSwyQ0FBcUk7QUFDckksaUNBQWlEO0FBQ2pELHVDQUFrRDtBQUdsRCxNQUFhLHFCQUFxQjtJQVFoQyxZQUFvQixFQUNsQiw0QkFBNEIsRUFDNUIsT0FBTyxFQUNQLFlBQVksRUFDWixvQkFBb0IsR0FNckI7UUFDQyxJQUFJLENBQUMscUJBQXFCLEdBQUcsb0JBQW9CLENBQUM7UUFDbEQsSUFBSSxDQUFDLFFBQVEsR0FBRyxZQUFZLENBQUM7UUFDN0IsSUFBSSxDQUFDLFFBQVEsR0FBRyxPQUFPLENBQUM7UUFDeEIsSUFBSSxDQUFDLFFBQVEsR0FBRyw0QkFBNEIsQ0FBQztJQUMvQyxDQUFDO0lBRUQ7Ozs7OztPQU1HO0lBQ0gsTUFBTSxDQUFPLGlCQUFpQixDQUM1QixhQUFxQixFQUNyQixZQUF1QyxFQUN2QyxVQUEwQzs7WUFFMUMsSUFBQSxnREFBeUMsRUFBQyxVQUFVLENBQUMsQ0FBQztZQUN0RCxNQUFNLElBQUEsOEJBQXVCLEVBQUMsWUFBWSxDQUFDLENBQUM7WUFDNUMsSUFBSSxDQUFDLGFBQWEsSUFBSSxDQUFDLGFBQWEsQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQztnQkFDdEQsTUFBTSxJQUFJLEtBQUssQ0FBQyxrQkFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ3JDLENBQUM7WUFDRCxNQUFNLG9CQUFvQixHQUFHLE1BQU0sNENBQW9CLENBQUMsWUFBWSxDQUFDLGFBQWEsQ0FBQyxDQUFDO1lBQ3BGLE9BQU8scUJBQXFCLENBQUMsd0JBQXdCLENBQUMsb0JBQW9CLEVB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