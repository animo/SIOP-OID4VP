import { IPresentationDefinition } from '@sphereon/pex';
import { Format } from '@sphereon/pex-models';
import { Hasher, PresentationSubmission, W3CVerifiablePresentation, WrappedVerifiablePresentation } from '@sphereon/ssi-types';
import { AuthorizationRequest } from '../authorization-request';
import { AuthorizationResponsePayload, IDTokenPayload, VerifiedOpenID4VPSubmission } from '../types';
import { AuthorizationResponse } from './AuthorizationResponse';
import { AuthorizationResponseOpts, PresentationDefinitionWithLocation, PresentationVerificationCallback, VerifyAuthorizationResponseOpts } from './types';
export declare const verifyPresentations: (authorizationResponse: AuthorizationResponse, verifyOpts: VerifyAuthorizationResponseOpts) => Promise<VerifiedOpenID4VPSubmission | null>;
export declare const extractPresentationsFromAuthorizationResponse: (response: AuthorizationResponse, opts?: {
    hasher?: Hasher;
}) => Promise<WrappedVerifiablePresentation[]>;
export declare const createPresentationSubmission: (verifiablePresentations: W3CVerifiablePresentation[], opts?: {
    presentationDefinitions: (PresentationDefinitionWithLocation | IPresentationDefinition)[];
}) => Promise<PresentationSubmission>;
export declare const putPresentationSubmissionInLocation: (authorizationRequest: AuthorizationRequest, responsePayload: AuthorizationResponsePayload, resOpts: AuthorizationResponseOpts, idTokenPayload?: IDTokenPayload) => Promise<void>;
export declare const assertValidVerifiablePresentations: (args: {
    presentationDefinitions: PresentationDefinitionWithLocation[];
    presentations: WrappedVerifiablePresentation[];
    verificationCallback: PresentationVerificationCallback;
    opts?: {
        limitDisclosureSignatureSuites?: string[];
        restrictToFormats?: Format;
        restrictToDIDMethods?: string[];
        presentationSubmission?: PresentationSubmission;
        hasher?: Hasher;
    };
}) => Promise<void>;
