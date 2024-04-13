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
exports.assertValidVerifiablePresentations = exports.putPresentationSubmissionInLocation = exports.createPresentationSubmission = exports.extractPresentationsFromAuthorizationResponse = exports.verifyPresentations = void 0;
const pex_1 = require("@sphereon/pex");
const ssi_types_1 = require("@sphereon/ssi-types");
const did_jwt_1 = require("did-jwt");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const PresentationExchange_1 = require("./PresentationExchange");
const types_2 = require("./types");
function extractNonceFromWrappedVerifiablePresentation(wrappedVp) {
    var _a;
    // SD-JWT uses kb-jwt for the nonce
    if (ssi_types_1.CredentialMapper.isWrappedSdJwtVerifiablePresentation(wrappedVp)) {
        // TODO: replace this once `kbJwt.payload` is available on the decoded sd-jwt (pr in ssi-sdk)
        // If it doesn't end with ~, it contains a kbJwt
        if (!wrappedVp.presentation.compactSdJwtVc.endsWith('~')) {
            const kbJwt = wrappedVp.presentation.compactSdJwtVc.split('~').pop();
            const { payload } = (0, did_jwt_1.decodeJWT)(kbJwt);
            return payload.nonce;
        }
        // No kb-jwt means no nonce (error will be handled later)
        return undefined;
    }
    if (wrappedVp.format === 'jwt_vp') {
        return wrappedVp.decoded.nonce;
    }
    // For LDP-VP a challenge is also fine
    if (wrappedVp.format === 'ldp_vp') {
        const w3cPresentation = wrappedVp.decoded;
        const proof = Array.isArray(w3cPresentation.proof) ? w3cPresentation.proof[0] : w3cPresentation.proof;
        return (_a = proof.nonce) !== null && _a !== void 0 ? _a : proof.challenge;
    }
    return undefined;
}
const verifyPresentations = (authorizationResponse, verifyOpts) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d;
    const presentations = yield (0, exports.extractPresentationsFromAuthorizationResponse)(authorizationResponse, { hasher: verifyOpts.hasher });
    const presentationDefinitions = verifyOpts.presentationDefinitions
        ? Array.isArray(verifyOpts.presentationDefinitions)
            ? verifyOpts.presentationDefinitions
            : [verifyOpts.presentationDefinitions]
        : [];
    let idPayload;
    if (authorizationResponse.idToken) {
        idPayload = yield authorizationResponse.idToken.payload();
    }
    // todo: Probably wise to check against request for the location of the submission_data
    const presentationSubmission = (_b = (_a = idPayload === null || idPayload === void 0 ? void 0 : idPayload._vp_token) === null || _a === void 0 ? void 0 : _a.presentation_submission) !== null && _b !== void 0 ? _b : authorizationResponse.payload.presentation_submission;
    yield (0, exports.assertValidVerifiablePresentations)({
        presentationDefinitions,
        presentations,
        verificationCallback: verifyOpts.verification.presentationVerificationCallback,
        opts: {
            presentationSubmission,
            restrictToFormats: verifyOpts.restrictToFormats,
            restrictToDIDMethods: verifyOpts.restrictToDIDMethods,
            hasher: verifyOpts.hasher,
        },
    });
    // If there are no presentations, and the `assertValidVerifiablePresentations` did not fail
    // it means there's no oid4vp response and also not requested
    if (presentations.length === 0) {
        return null;
    }
    const nonces = new Set(presentations.map(extractNonceFromWrappedVerifiablePresentation));
    if (presentations.length > 0 && nonces.size !== 1) {
        throw Error(`${nonces.size} nonce values found for ${presentations.length}. Should be 1`);
    }
    // Nonce may be undefined
    const nonce = Array.from(nonces)[0];
    if (typeof nonce !== 'string') {
        throw new Error('Expected all presentations to contain a nonce value');
    }
    const revocationVerification = ((_c = verifyOpts.verification) === null || _c === void 0 ? void 0 : _c.revocationOpts)
        ? verifyOpts.verification.revocationOpts.revocationVerification
        : types_1.RevocationVerification.IF_PRESENT;
    if (revocationVerification !== types_1.RevocationVerification.NEVER) {
        if (!((_d = verifyOpts.verification.revocationOpts) === null || _d === void 0 ? void 0 : _d.revocationVerificationCallback)) {
            throw Error(`Please provide a revocation callback as revocation checking of credentials and presentations is not disabled`);
        }
        for (const vp of presentations) {
            yield (0, helpers_1.verifyRevocation)(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
        }
    }
    return { nonce, presentations, presentationDefinitions, submissionData: presentationSubmission };
});
exports.verifyPresentations = verifyPresentations;
const extractPresentationsFromAuthorizationResponse = (response, opts) => __awaiter(void 0, void 0, void 0, function* () {
    const wrappedVerifiablePresentations = [];
    if (response.payload.vp_token) {
        const presentations = Array.isArray(response.payload.vp_token) ? response.payload.vp_token : [response.payload.vp_token];
        for (const presentation of presentations) {
            wrappedVerifiablePresentations.push(ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(presentation, { hasher: opts === null || opts === void 0 ? void 0 : opts.hasher }));
        }
    }
    return wrappedVerifiablePresentations;
});
exports.extractPresentationsFromAuthorizationResponse = extractPresentationsFromAuthorizationResponse;
const createPresentationSubmission = (verifiablePresentations, opts) => __awaiter(void 0, void 0, void 0, function* () {
    var _e, _f;
    let submission_data;
    for (const verifiablePresentation of verifiablePresentations) {
        const wrappedPresentation = ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation);
        let submission = ssi_types_1.CredentialMapper.isWrappedW3CVerifiablePresentation(wrappedPresentation) &&
            ((_f = (_e = wrappedPresentation.presentation.presentation_submission) !== null && _e !== void 0 ? _e : wrappedPresentation.decoded.presentation_submission) !== null && _f !== void 0 ? _f : (typeof wrappedPresentation.original !== 'string' && wrappedPresentation.original.presentation_submission));
        if (typeof submission === 'string') {
            submission = JSON.parse(submission);
        }
        if (!submission && (opts === null || opts === void 0 ? void 0 : opts.presentationDefinitions)) {
            console.log(`No submission_data in VPs and not provided. Will try to deduce, but it is better to create the submission data beforehand`);
            for (const definitionOpt of opts.presentationDefinitions) {
                const definition = 'definition' in definitionOpt ? definitionOpt.definition : definitionOpt;
                const result = new pex_1.PEX().evaluatePresentation(definition, wrappedPresentation.original, { generatePresentationSubmission: true });
                if (result.areRequiredCredentialsPresent) {
                    submission = result.value;
                    break;
                }
            }
        }
        if (!submission) {
            throw Error('Verifiable Presentation has no submission_data, it has not been provided separately, and could also not be deduced');
        }
        // let's merge all submission data into one object
        if (!submission_data) {
            submission_data = submission;
        }
        else {
            // We are pushing multiple descriptors into one submission_data, as it seems this is something which is assumed in OpenID4VP, but not supported in Presentation Exchange (a single VP always has a single submission_data)
            Array.isArray(submission_data.descriptor_map)
                ? submission_data.descriptor_map.push(...submission.descriptor_map)
                : (submission_data.descriptor_map = [...submission.descriptor_map]);
        }
    }
    if (typeof submission_data === 'string') {
        submission_data = JSON.parse(submission_data);
    }
    return submission_data;
});
exports.createPresentationSubmission = createPresentationSubmission;
const putPresentationSubmissionInLocation = (authorizationRequest, responsePayload, resOpts, idTokenPayload) => __awaiter(void 0, void 0, void 0, function* () {
    var _g, _h, _j, _k, _l, _m;
    const version = yield authorizationRequest.getSupportedVersion();
    const idTokenType = yield authorizationRequest.containsResponseType(types_1.ResponseType.ID_TOKEN);
    const authResponseType = yield authorizationRequest.containsResponseType(types_1.ResponseType.VP_TOKEN);
    // const requestPayload = await authorizationRequest.mergedPayloads();
    if (!resOpts.presentationExchange) {
        return;
    }
    else if (resOpts.presentationExchange.verifiablePresentations.length === 0) {
        throw Error('Presentation Exchange options set, but no verifiable presentations provided');
    }
    if (!resOpts.presentationExchange.presentationSubmission &&
        (!resOpts.presentationExchange.verifiablePresentations || resOpts.presentationExchange.verifiablePresentations.length === 0)) {
        throw Error(`Either a presentationSubmission or verifiable presentations are needed at this point`);
    }
    const submissionData = (_g = resOpts.presentationExchange.presentationSubmission) !== null && _g !== void 0 ? _g : (yield (0, exports.createPresentationSubmission)(resOpts.presentationExchange.verifiablePresentations, {
        presentationDefinitions: yield authorizationRequest.getPresentationDefinitions(),
    }));
    const location = (_j = (_h = resOpts.presentationExchange) === null || _h === void 0 ? void 0 : _h.vpTokenLocation) !== null && _j !== void 0 ? _j : (idTokenType && version < types_1.SupportedVersion.SIOPv2_D11 ? types_2.VPTokenLocation.ID_TOKEN : types_2.VPTokenLocation.AUTHORIZATION_RESPONSE);
    switch (location) {
        case types_2.VPTokenLocation.TOKEN_RESPONSE: {
            throw Error('Token response for VP token is not supported yet');
        }
        case types_2.VPTokenLocation.ID_TOKEN: {
            if (!idTokenPayload) {
                throw Error('Cannot place submission data _vp_token in id token if no id token is present');
            }
            else if (version >= types_1.SupportedVersion.SIOPv2_D11) {
                throw Error(`This version of the OpenID4VP spec does not allow to store the vp submission data in the ID token`);
            }
            else if (!idTokenType) {
                throw Error(`Cannot place vp token in ID token as the RP didn't provide an "openid" scope in the request`);
            }
            if ((_k = idTokenPayload._vp_token) === null || _k === void 0 ? void 0 : _k.presentation_submission) {
                if (submissionData !== idTokenPayload._vp_token.presentation_submission) {
                    throw Error('Different submission data was provided as an option, but exising submission data was already present in the id token');
                }
            }
            else {
                if (!idTokenPayload._vp_token) {
                    idTokenPayload._vp_token = { presentation_submission: submissionData };
                }
                else {
                    idTokenPayload._vp_token.presentation_submission = submissionData;
                }
            }
            break;
        }
        case types_2.VPTokenLocation.AUTHORIZATION_RESPONSE: {
            if (!authResponseType) {
                throw Error('Cannot place vp token in Authorization Response as there is no vp_token scope in the auth request');
            }
            if (responsePayload.presentation_submission) {
                if (submissionData !== responsePayload.presentation_submission) {
                    throw Error('Different submission data was provided as an option, but exising submission data was already present in the authorization response');
                }
            }
            else {
                responsePayload.presentation_submission = submissionData;
            }
        }
    }
    responsePayload.vp_token =
        ((_l = resOpts.presentationExchange) === null || _l === void 0 ? void 0 : _l.verifiablePresentations.length) === 1
            ? resOpts.presentationExchange.verifiablePresentations[0]
            : (_m = resOpts.presentationExchange) === null || _m === void 0 ? void 0 : _m.verifiablePresentations;
});
exports.putPresentationSubmissionInLocation = putPresentationSubmissionInLocation;
const assertValidVerifiablePresentations = (args) => __awaiter(void 0, void 0, void 0, function* () {
    if ((!args.presentationDefinitions || args.presentationDefinitions.filter((a) => a.definition).length === 0) &&
        (!args.presentations || (Array.isArray(args.presentations) && args.presentations.filter((vp) => vp.presentation).length === 0))) {
        return;
    }
    PresentationExchange_1.PresentationExchange.assertValidPresentationDefinitionWithLocations(args.presentationDefinitions);
    const presentationsWithFormat = args.presentations;
    if (args.presentationDefinitions && args.presentationDefinitions.length && (!presentationsWithFormat || presentationsWithFormat.length === 0)) {
        throw new Error(types_1.SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
    }
    else if ((!args.presentationDefinitions || args.presentationDefinitions.length === 0) &&
        presentationsWithFormat &&
        presentationsWithFormat.length > 0) {
        throw new Error(types_1.SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP);
    }
    else if (args.presentationDefinitions && presentationsWithFormat && args.presentationDefinitions.length != presentationsWithFormat.length) {
        throw new Error(types_1.SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
    }
    else if (args.presentationDefinitions && !args.opts.presentationSubmission) {
        throw new Error(`No presentation submission present. Please use presentationSubmission opt argument!`);
    }
    else if (args.presentationDefinitions && presentationsWithFormat) {
        yield PresentationExchange_1.PresentationExchange.validatePresentationsAgainstDefinitions(args.presentationDefinitions, presentationsWithFormat, args.verificationCallback, args.opts);
    }
});
exports.assertValidVerifiablePresentations = assertValidVerifiablePresentations;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiT3BlbklENFZQLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2F1dGhvcml6YXRpb24tcmVzcG9uc2UvT3BlbklENFZQLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7OztBQUFBLHVDQUE2RDtBQUU3RCxtREFPNkI7QUFDN0IscUNBQW9DO0FBR3BDLHdDQUE4QztBQUM5QyxvQ0FRa0I7QUFHbEIsaUVBQThEO0FBQzlELG1DQU1pQjtBQUVqQixTQUFTLDZDQUE2QyxDQUFDLFNBQXdDOztJQUM3RixtQ0FBbUM7SUFDbkMsSUFBSSw0QkFBZ0IsQ0FBQyxvQ0FBb0MsQ0FBQyxTQUFTLENBQUMsRUFBRSxDQUFDO1FBQ3JFLDZGQUE2RjtRQUM3RixnREFBZ0Q7UUFDaEQsSUFBSSxDQUFDLFNBQVMsQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDO1lBQ3pELE1BQU0sS0FBSyxHQUFHLFNBQVMsQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLEVBQUUsQ0FBQztZQUNyRSxNQUFNLEVBQUUsT0FBTyxFQUFFLEdBQUcsSUFBQSxtQkFBUyxFQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3JDLE9BQU8sT0FBTyxDQUFDLEtBQUssQ0FBQztRQUN2QixDQUFDO1FBRUQseURBQXlEO1FBQ3pELE9BQU8sU0FBUyxDQUFDO0lBQ25CLENBQUM7SUFFRCxJQUFJLFNBQVMsQ0FBQyxNQUFNLEtBQUssUUFBUSxFQUFFLENBQUM7UUFDbEMsT0FBTyxTQUFTLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQztJQUNqQyxDQUFDO0lBRUQsc0NBQXNDO0lBQ3RDLElBQUksU0FBUyxDQUFDLE1BQU0sS0FBSyxRQUFRLEVBQUUsQ0FBQztRQUNsQyxNQUFNLGVBQWUsR0FBRyxTQUFTLENBQUMsT0FBa0MsQ0FBQztRQUNyRSxNQUFNLEtBQUssR0FBRyxLQUFLLENB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