import { Presentation, SelectResults, Validated, VerifiableCredential, VP } from '@sphereon/pe-js';
import Ajv from 'ajv';
import fetch from 'cross-fetch';

import AuthenticationRequest from './AuthenticationRequest';
import AuthenticationResponse from './AuthenticationResponse';
import OPBuilder from './OPBuilder';
import { PresentationExchangeAgent } from './PresentationExchangeAgent';
import { getResolver } from './functions/DIDResolution';
import { extractDataFromPath } from './functions/ObjectUtils';
import { AuthenticationResponseOptsSchema } from './schemas/AuthenticationResponseOpts.schema';
import { SIOP, SIOPErrors } from './types';
import {
  AuthenticationRequestPayload,
  AuthenticationResponseOpts,
  AuthenticationResponseWithJWT,
  ExternalVerification,
  InternalVerification,
  ParsedAuthenticationRequestURI,
  ResponseRegistrationOpts,
  UrlEncodingFormat,
  VerificationMode,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
} from './types/SIOP.types';

const ajv = new Ajv();

const validate = ajv.compile(AuthenticationResponseOptsSchema);

export class OP {
  private readonly authResponseOpts: AuthenticationResponseOpts;
  private readonly verifyAuthRequestOpts: Partial<VerifyAuthenticationRequestOpts>;
  private presentationExchangeAgent: PresentationExchangeAgent = new PresentationExchangeAgent();

  public constructor(opts: {
    builder?: OPBuilder;
    responseOpts?: AuthenticationResponseOpts;
    verifyOpts?: VerifyAuthenticationRequestOpts;
  }) {
    this.authResponseOpts = { ...createResponseOptsFromBuilderOrExistingOpts(opts) };
    this.verifyAuthRequestOpts = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) };
  }

  public async createAuthenticationResponse(
    requestJwtorUri: string,
    opts?: {
      nonce?: string;
      state?: string;
      // audience: string;
      verification?: InternalVerification | ExternalVerification;
    }
  ): Promise<AuthenticationResponseWithJWT> {
    if (!requestJwtorUri) {
      throw new Error(SIOPErrors.BAD_PARAMS);
    }
    const jwt = requestJwtorUri.startsWith('ey') ? requestJwtorUri : (await parseAndResolveUri(requestJwtorUri)).jwt;

    return AuthenticationResponse.createJWTFromRequestJWT(
      jwt,
      this.newAuthenticationResponseOpts(opts),
      this.newVerifyAuthenticationRequestOpts(opts)
    );
  }

  public createAuthenticationResponseFromVerifiedRequest(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    responseOpts?: {
      nonce?: string;
      state?: string;
      // audience: string;
      verification?: InternalVerification | ExternalVerification;
    }
  ): Promise<AuthenticationResponseWithJWT> {
    return AuthenticationResponse.createJWTFromVerifiedRequest(
      verifiedJwt,
      this.newAuthenticationResponseOpts(responseOpts)
    );
  }

  public verifyAuthenticationRequest(
    requestJwt: string,
    opts?: { /*audience?: string;*/ nonce?: string; verification?: InternalVerification | ExternalVerification }
  ): Promise<VerifiedAuthenticationRequestWithJWT> {
    return AuthenticationRequest.verifyJWT(requestJwt, this.newVerifyAuthenticationRequestOpts(opts));
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param encodedUri
   */
  public async parseAuthenticationRequestURI(encodedUri: string): Promise<ParsedAuthenticationRequestURI> {
    const { requestPayload, jwt, registration } = await parseAndResolveUri(encodedUri);

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      jwt,
      requestPayload,
      registration,
    };
  }

  public async newAuthenticationResponseWithSelected(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    verifiableCredentials: VerifiableCredential[],
    holderDID: string,
    responseOpts?: {
      nonce?: string;
      state?: string;
      // audience: string;
      verification?: InternalVerification | ExternalVerification;
    }
  ): Promise<AuthenticationResponseWithJWT> {
    const optionalPD = extractDataFromPath(verifiedJwt.payload, '$..presentation_definition');
    if (optionalPD && optionalPD.length) {
      const ps = this.presentationExchangeAgent.submissionFrom(optionalPD[0].value, verifiableCredentials);
      responseOpts['vp'] = new VP(
        new Presentation(null, ps, ['VerifiableCredential'], verifiableCredentials, holderDID, null)
      );
    }
    return AuthenticationResponse.createJWTFromVerifiedRequest(
      verifiedJwt,
      this.newAuthenticationResponseOpts(responseOpts)
    );
  }

  public newAuthenticationResponseOpts(opts?: { nonce?: string; state?: string }): AuthenticationResponseOpts {
    const state = opts?.state;
    const nonce = opts?.nonce;
    return {
      ...this.authResponseOpts,
      nonce,
      state,
    };
  }

  public newVerifyAuthenticationRequestOpts(opts?: {
    nonce?: string;
    verification?: InternalVerification | ExternalVerification;
  }): VerifyAuthenticationRequestOpts {
    return {
      ...this.verifyAuthRequestOpts,
      nonce: opts?.nonce || this.verifyAuthRequestOpts.nonce,
      verification: opts?.verification || this.verifyAuthRequestOpts.verification,
    };
  }

  public async selectVerifiableCredentialsForSubmission(
    authenticationRequestPayload: AuthenticationRequestPayload,
    verifiableCredentials: VerifiableCredential[],
    holderDid: string
  ): Promise<SelectResults> {
    const optionalPD = extractDataFromPath(authenticationRequestPayload, '$..presentation_definition');
    if (optionalPD && optionalPD.length) {
      const validationResult: Validated | Validated[] = this.presentationExchangeAgent.validatePresentationDefinition(
        optionalPD[0].value
      );
      if (validationResult[0].message != 'ok') {
        throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
      }
    }
    return this.presentationExchangeAgent.selectFrom(optionalPD[0].value, verifiableCredentials, holderDid);
  }

  public static fromOpts(responseOpts: AuthenticationResponseOpts, verifyOpts: VerifyAuthenticationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts });
  }

  public static builder() {
    return new OPBuilder();
  }
}

async function parseAndResolveUri(encodedUri: string) {
  const requestPayload = AuthenticationRequest.parseURI(encodedUri);
  const jwt = requestPayload.request || (await (await fetch(requestPayload.request_uri)).text());
  const registration = requestPayload.registration || (await (await fetch(requestPayload.registration_uri)).json());
  return { requestPayload, jwt, registration };
}

function createResponseOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  responseOpts?: AuthenticationResponseOpts;
}) {
  const responseOpts: AuthenticationResponseOpts = opts.builder
    ? {
        registration: opts.builder.responseRegistration as ResponseRegistrationOpts,
        did: opts.builder.signatureType.did,
        expiresIn: opts.builder.expiresIn,
        signatureType: opts.builder.signatureType,
        responseMode: opts.builder.responseMode,
      }
    : { ...opts.responseOpts };

  const valid = validate(responseOpts);
  if (!valid) {
    throw new Error('OP builder validation error: ' + JSON.stringify(validate.errors));
  }
  return responseOpts;
}

function createVerifyRequestOptsFromBuilderOrExistingOpts(opts: {
  builder?: OPBuilder;
  verifyOpts?: Partial<VerifyAuthenticationRequestOpts>;
}) {
  return opts.builder
    ? {
        verification: {
          mode: VerificationMode.INTERNAL,
          resolveOpts: {
            didMethods: opts.builder.didMethods,
            resolver: getResolver({ didMethods: opts.builder.didMethods }),
          },
        },
      }
    : opts.verifyOpts;
}
