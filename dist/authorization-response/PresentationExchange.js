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
exports.PresentationExchange = void 0;
const pex_1 = require("@sphereon/pex");
const ssi_types_1 = require("@sphereon/ssi-types");
const helpers_1 = require("../helpers");
const types_1 = require("../types");
const types_2 = require("./types");
class PresentationExchange {
    constructor(opts) {
        this.allDIDs = opts.allDIDs;
        this.allVerifiableCredentials = opts.allVerifiableCredentials;
        this.pex = new pex_1.PEX({ hasher: opts.hasher });
    }
    /**
     * Construct presentation submission from selected credentials
     * @param presentationDefinition payload object received by the OP from the RP
     * @param selectedCredentials
     * @param presentationSignCallback
     * @param options
     */
    createVerifiablePresentation(presentationDefinition, selectedCredentials, presentationSignCallback, 
    // options2?: { nonce?: string; domain?: string, proofType?: IProofType, verificationMethod?: string, signatureKeyEncoding?: KeyEncoding },
    options) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c, _d, _e, _f;
            if (!presentationDefinition) {
                throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
            }
            const signOptions = Object.assign(Object.assign({}, options), { presentationSubmissionLocation: pex_1.PresentationSubmissionLocation.EXTERNAL, proofOptions: Object.assign(Object.assign({}, options.proofOptions), { proofPurpose: (_b = (_a = options === null || options === void 0 ? void 0 : options.proofOptions) === null || _a === void 0 ? void 0 : _a.proofPurpose) !== null && _b !== void 0 ? _b : ssi_types_1.IProofPurpose.authentication, type: (_d = (_c = options === null || options === void 0 ? void 0 : options.proofOptions) === null || _c === void 0 ? void 0 : _c.type) !== null && _d !== void 0 ? _d : ssi_types_1.IProofType.EcdsaSecp256k1Signature2019 }), signatureOptions: Object.assign(Object.assign({}, options.signatureOptions), { 
                    // verificationMethod: options?.signatureOptions?.verificationMethod,
                    keyEncoding: (_f = (_e = options === null || options === void 0 ? void 0 : options.signatureOptions) === null || _e === void 0 ? void 0 : _e.keyEncoding) !== null && _f !== void 0 ? _f : pex_1.KeyEncoding.Hex }) });
            return yield this.pex.verifiablePresentationFrom(presentationDefinition, selectedCredentials, presentationSignCallback, signOptions);
        });
    }
    /**
     * This method will be called from the OP when we are certain that we have a
     * PresentationDefinition object inside our requestPayload
     * Finds a set of `VerifiableCredential`s from a list supplied to this class during construction,
     * matching presentationDefinition object found in the requestPayload
     * if requestPayload doesn't contain any valid presentationDefinition throws an error
     * if PEX library returns any error in the process, throws the error
     * returns the SelectResults object if successful
     * @param presentationDefinition object received by the OP from the RP
     * @param opts
     */
    selectVerifiableCredentialsForSubmission(presentationDefinition, opts) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            if (!presentationDefinition) {
                throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
            }
            else if (!this.allVerifiableCredentials || this.allVerifiableCredentials.length == 0) {
                throw new Error(`${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, no VCs were provided`);
            }
            const selectResults = this.pex.selectFrom(presentationDefinition, this.allVerifiableCredentials, Object.assign(Object.assign({}, opts), { holderDIDs: (_a = opts === null || opts === void 0 ? void 0 : opts.holderDIDs) !== null && _a !== void 0 ? _a : this.allDIDs, 
                // fixme limited disclosure
                limitDisclosureSignatureSuites: [] }));
            if (selectResults.areRequiredCredentialsPresent === pex_1.Status.ERROR) {
                throw new Error(`message: ${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`);
            }
            return selectResults;
        });
    }
    /**
     * validatePresentationAgainstDefinition function is called mainly by the RP
     * after receiving the VP from the OP
     * @param presentationDefinition object containing PD
     * @param verifiablePresentation
     * @param opts
     */
    static validatePresentationAgainstDefinition(presentationDefinition, verifiablePresentation, opts) {
        return __awaiter(this, void 0, void 0, function* () {
            const wvp = typeof verifiablePresentation === 'object' && 'original' in verifiablePresentation
                ? verifiablePresentation
                : ssi_types_1.CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation);
            if (!presentationDefinition) {
                throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
            }
            else if (!wvp ||
                !wvp.presentation ||
                (ssi_types_1.CredentialMapper.isWrappedW3CVerifiablePresentation(wvp) &&
                    (!wvp.presentation.verifiableCredential || wvp.presentation.verifiableCredential.length === 0))) {
                throw new Error(types_1.SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
            }
            // console.log(`Presentation (validate): ${JSON.stringify(verifiablePresentation)}`);
            const evaluationResults = new pex_1.PEX({ hasher: opts === null || opts === void 0 ? void 0 : opts.hasher }).evaluatePresentation(presentationDefinition, wvp.original, opts);
            if (evaluationResults.errors.length) {
                throw new Error(`message: ${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`);
            }
            return evaluationResults;
        });
    }
    static assertValidPresentationSubmission(presentationSubmission) {
        const validationResult = pex_1.PEX.validateSubmission(presentationSubmission);
        if (validationResult[0].message != 'ok') {
            throw new Error(`${types_1.SIOPErrors.RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID}, details ${JSON.stringify(validationResult[0])}`);
        }
    }
    /**
     * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
     * throws exception if the PresentationDefinition is not valid
     * returns null if no property named "presentation_definition" is found
     * returns a PresentationDefinition if a valid instance found
     * @param authorizationRequestPayload object that can have a presentation_definition inside
     * @param version
     */
    static findValidPresentationDefinitions(authorizationRequestPayload, version) {
        return __awaiter(this, void 0, void 0, function* () {
            const allDefinitions = [];
            function extractDefinitionFromVPToken() {
                return __awaiter(this, void 0, void 0, function* () {
                    const vpTokens = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$..vp_token.presentation_definition').map((d) => d.value);
                    const vpTokenRefs = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$..vp_token.presentation_definition_uri');
                    if (vpTokens && vpTokens.length && vpTokenRefs && vpTokenRefs.length) {
                        throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE);
                    }
                    if (vpTokens && vpTokens.length) {
                        vpTokens.forEach((vpToken) => {
                            if (allDefinitions.find((value) => value.definition.id === vpToken.id)) {
                                console.log(`Warning. We encountered presentation definition with id ${vpToken.id}, more then once whilst processing! Make sure your payload is valid!`);
                                return;
                            }
                            PresentationExchange.assertValidPresentationDefinition(vpToken);
                            allDefinitions.push({
                                definition: vpToken,
                                location: types_2.PresentationDefinitionLocation.CLAIMS_VP_TOKEN,
                                version,
                            });
                        });
                    }
                    else if (vpTokenRefs && vpTokenRefs.length) {
                        for (const vpTokenRef of vpTokenRefs) {
                            const pd = (yield (0, helpers_1.getWithUrl)(vpTokenRef.value));
                            if (allDefinitions.find((value) => value.definition.id === pd.id)) {
                                console.log(`Warning. We encountered presentation definition with id ${pd.id}, more then once whilst processing! Make sure your payload is valid!`);
                                return;
                            }
                            PresentationExchange.assertValidPresentationDefinition(pd);
                            allDefinitions.push({ definition: pd, location: types_2.PresentationDefinitionLocation.CLAIMS_VP_TOKEN, version });
                        }
                    }
                });
            }
            function addSingleToplevelPDToPDs(definition, version) {
                if (allDefinitions.find((value) => value.definition.id === definition.id)) {
                    console.log(`Warning. We encountered presentation definition with id ${definition.id}, more then once whilst processing! Make sure your payload is valid!`);
                    return;
                }
                PresentationExchange.assertValidPresentationDefinition(definition);
                allDefinitions.push({
                    definition,
                    location: types_2.PresentationDefinitionLocation.TOPLEVEL_PRESENTATION_DEF,
                    version,
                });
            }
            function extractDefinitionFromTopLevelDefinitionProperty(version) {
                return __awaiter(this, void 0, void 0, function* () {
                    const definitions = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition');
                    const definitionsFromList = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition[*]');
                    const definitionRefs = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition_uri');
                    const definitionRefsFromList = (0, helpers_1.extractDataFromPath)(authorizationRequestPayload, '$.presentation_definition_uri[*]');
                    const hasPD = (definitions && definitions.length > 0) || (definitionsFromList && definitionsFromList.length > 0);
                    const hasPdRef = (definitionRefs && definitionRefs.length > 0) || (definitionRefsFromList && definitionRefsFromList.length > 0);
                    if (hasPD && hasPdRef) {
                        throw new Error(types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_BY_REF_AND_VALUE_NON_EXCLUSIVE);
                    }
                    if (definitions && definitions.length > 0) {
                        definitions.forEach((definition) => {
                            addSingleToplevelPDToPDs(definition.value, version);
                        });
                    }
                    else if (definitionsFromList && definitionsFromList.length > 0) {
                        definitionsFromList.forEach((definition) => {
                            addSingleToplevelPDToPDs(definition.value, version);
                        });
                    }
                    else if (definitionRefs && definitionRefs.length > 0) {
                        for (const definitionRef of definitionRefs) {
                            const pd = yield (0, helpers_1.getWithUrl)(definitionRef.value);
                            addSingleToplevelPDToPDs(pd, version);
                        }
                    }
                    else if (definitionsFromList && definitionRefsFromList.length > 0) {
                        for (const definitionRef of definitionRefsFromList) {
                            const pd = yield (0, helpers_1.getWithUrl)(definitionRef.value);
                            addSingleToplevelPDToPDs(pd, version);
                        }
                    }
                });
            }
            if (authorizationRequestPayload) {
                if (!version || version < types_1.SupportedVersion.SIOPv2_D11) {
                    yield extractDefinitionFromVPToken();
                }
                yield extractDefinitionFromTopLevelDefinitionProperty();
            }
            return allDefinitions;
        });
    }
    static assertValidPresentationDefinitionWithLocations(definitionsWithLocations) {
        if (definitionsWithLocations && definitionsWithLocations.length > 0) {
            definitionsWithLocations.forEach((definitionWithLocation) => PresentationExchange.assertValidPresentationDefinition(definitionWithLocation.definition));
        }
    }
    static assertValidPresentationDefinition(presentationDefinition) {
        const validationResult = pex_1.PEX.validateDefinition(presentationDefinition);
        if (validationResult[0].message != 'ok') {
            throw new Error(`${types_1.SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
        }
    }
    static validatePresentationsAgainstDefinitions(definitions, vpPayloads, verifyPresentationCallback, opts) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!definitions || !vpPayloads || !definitions.length || definitions.length !== vpPayloads.length) {
                throw new Error(types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
            }
            yield Promise.all(definitions.map((pd) => __awaiter(this, void 0, void 0, function* () { return yield PresentationExchange.validatePresentationsAgainstDefinition(pd.definition, vpPayloads, verifyPresentationCallback, opts); })));
        });
    }
    static validatePresentationsAgainstDefinition(definition, vpPayloads, verifyPresentationCallback, opts) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            const pex = new pex_1.PEX({ hasher: opts === null || opts === void 0 ? void 0 : opts.hasher });
            function filterOutCorrectPresentation() {
                return __awaiter(this, void 0, void 0, function* () {
                    //TODO: add support for multiple VPs here
                    const matchingVps = vpPayloads.map((vpw) => __awaiter(this, void 0, void 0, function* () {
                        var _a;
                        const presentationSubmission = (_a = opts === null || opts === void 0 ? void 0 : opts.presentationSubmission) !== null && _a !== void 0 ? _a : (ssi_types_1.CredentialMapper.isWrappedW3CVerifiablePresentation(vpw) ? vpw.presentation.presentation_submission : undefined);
                        const presentation = vpw.presentation;
                        if (!definition) {
                            throw new Error(types_1.SIOPErrors.NO_PRESENTATION_SUBMISSION);
                        }
                        else if (!vpw.presentation ||
                            (ssi_types_1.CredentialMapper.isWrappedW3CVerifiablePresentation(vpw) &&
                                (!vpw.presentation.verifiableCredential || vpw.presentation.verifiableCredential.length === 0))) {
                            throw new Error(types_1.SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
                        }
                        // The verifyPresentationCallback function is mandatory for RP only,
                        // So the behavior here is to bypass it if not present
                        if (verifyPresentationCallback) {
                            try {
                                const verificationResult = yield verifyPresentationCallback(vpw.original, presentationSubmission);
                                if (!verificationResult.verified) {
                                    throw new Error(types_1.SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID + verificationResult.reason ? `. ${verificationResult.reason}` : '');
                                }
                            }
                            catch (error) {
                                throw new Error(types_1.SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID);
                            }
                        }
                        // console.log(`Presentation (filter): ${JSON.stringify(presentation)}`);
                        const evaluationResults = pex.evaluatePresentation(definition, vpw.original, Object.assign(Object.assign({}, opts), { presentationSubmission }));
                        const submission = evaluationResults.value;
                        if (!presentation || !submission) {
                            throw new Error(types_1.SIOPErrors.NO_PRESENTATION_SUBMISSION);
                        }
                        // No match
                        if (submission.definition_id !== definition.id) {
                            return undefined;
                        }
                        return vpw;
                    }));
                    // Wait for all results to finish and filter out undefined (no match) values
                    return (yield Promise.all(matchingVps)).filter((vp) => vp !== undefined);
                });
            }
            const checkedPresentations = yield filterOutCorrectPresentation();
            if (checkedPresentations.length !== 1) {
                throw new Error(`${types_1.SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}`);
            }
            const checkedPresentation = checkedPresentations[0];
            const presentation = checkedPresentation.presentation;
            // console.log(`Presentation (checked): ${JSON.stringify(checkedPresentation.presentation)}`);
            if (!checkedPresentation.presentation ||
                (ssi_types_1.CredentialMapper.isWrappedW3CVerifiablePresentation(checkedPresentation) &&
                    (!checkedPresentation.presentation.verifiableCredential || checkedPresentation.presentation.verifiableCredential.length === 0))) {
                throw new Error(types_1.SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS);
            }
            const presentationSubmission = (_a = opts === null || opts === void 0 ? void 0 : opts.presentationSubmission) !== null && _a !== void 0 ? _a : (ssi_types_1.CredentialMapper.isW3cPresentation(presentation) ? presentation.presentation_submission : undefined);
            const evaluationResults = pex.evaluatePresentation(definition, checkedPresentation.original, Object.assign(Object.assign({}, opts), { presentationSubmission }));
            PresentationExchange.assertValidPresentationSubmission(evaluationResults.value);
            yield PresentationExchange.validatePresentationAgainstDefinition(definition, checkedPresentation, Object.assign(Object.assign({}, opts), { presentationSubmission, hasher: opts === null || opts === void 0 ? void 0 : opts.hasher }));
        });
    }
}
exports.PresentationExchange = PresentationExchange;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUHJlc2VudGF0aW9uRXhjaGFuZ2UuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvYXV0aG9yaXphdGlvbi1yZXNwb25zZS9QcmVzZW50YXRpb25FeGNoYW5nZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7QUFBQSx1Q0FVdUI7QUFFdkIsbURBUzZCO0FBRTdCLHdDQUE2RDtBQUM3RCxvQ0FBcUY7QUFFckYsbUNBS2lCO0FBRWpCLE1BQWEsb0JBQW9CO0lBSy9CLFlBQVksSUFBdUc7UUFDakgsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDO1FBQzVCLElBQUksQ0FBQyx3QkFBd0IsR0FBRyxJQUFJLENBQUMsd0JBQXdCLENBQUM7UUFDOUQsSUFBSSxDQUFDLEdBQUcsR0FBRyxJQUFJLFNBQUcsQ0FBQyxFQUFFLE1BQU0sRUFBRSxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQztJQUM5QyxDQUFDO0lBRUQ7Ozs7OztPQU1HO0lBQ1UsNEJBQTRCLENBQ3ZDLHNCQUErQyxFQUMvQyxtQkFBbUQsRUFDbkQsd0JBQWtEO0lBQ2xELDJJQUEySTtJQUMzSSxPQUF3Qzs7O1lBRXhDLElBQUksQ0FBQyxzQkFBc0IsRUFBRSxDQUFDO2dCQUM1QixNQUFNLElBQUksS0FBSyxDQUFDLGtCQUFVLENBQUMsZ0RBQWdELENBQUMsQ0FBQztZQUMvRSxDQUFDO1lBRUQsTUFBTSxXQUFXLG1DQUNaLE9BQU8sS0FDViw4QkFBOEIsRUFBRSxvQ0FBOEIsQ0FBQyxRQUFRLEVBQ3ZFLFlBQVksa0NBQ1AsT0FBTyxDQUFDLFlBQVksS0FDdkIsWUFBWSxFQUFFLE1BQUEsTUFBQSxPQUFPLGFBQVAsT0FBTyx1QkFBUCxPQUFPLENBQUUsWUFBWSwwQ0FBRSxZQUFZLG1DQUFJLHlCQUFhLENBQUMsY0FBYyxFQUNqRixJQUFJLEVBQUUsTUFBQSxNQUFBLE9BQU8sYUFBUCxPQUFPLHVCQUFQLE9BQU8sQ0FBRSxZQUFZ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