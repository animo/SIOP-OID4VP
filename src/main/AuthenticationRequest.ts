import Ajv from 'ajv';
import { JWTHeader } from 'did-jwt';

import { assertValidRequestRegistrationOpts, createRequestRegistration } from './AuthenticationRequestRegistration';
import { PresentationExchange } from './PresentationExchange';
import {
  decodeUriAsJson,
  encodeJsonAsURI,
  getAudience,
  getNonce,
  getResolver,
  getState,
  getWithUrl,
  parseJWT,
  signDidJwtPayload,
  verifyDidJWT,
} from './functions';
import { RPRegistrationMetadataPayloadSchema } from './schemas';
import {
  AuthenticationRequestOpts,
  AuthenticationRequestPayload,
  AuthenticationRequestURI,
  AuthenticationRequestWithJWT,
  ClaimOpts,
  ClaimPayload,
  IdTokenClaimPayload,
  isExternalVerification,
  isInternalVerification,
  JWTPayload,
  PassBy,
  PresentationLocation,
  ResponseContext,
  ResponseMode,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SIOPErrors,
  UrlEncodingFormat,
  VerifiedAuthenticationRequestWithJWT,
  VerifyAuthenticationRequestOpts,
  VpTokenClaimPayload,
} from './types';

const ajv = new Ajv();
const validateRPRegistrationMetadata = ajv.compile(RPRegistrationMetadataPayloadSchema);

export default class AuthenticationRequest {
  /**
   * Create a signed URL encoded URI with a signed SIOP request token on RP side
   *
   * @param opts Request input data to build a  SIOP Request Token
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
   *
   * Normally you will want to use this method to create the request.
   */
  static async createURI(opts: AuthenticationRequestOpts): Promise<AuthenticationRequestURI> {
    const { jwt, payload } = await AuthenticationRequest.createJWT(opts);
    return createURIFromJWT(opts, payload, jwt);
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param uri
   */
  static parseURI(uri: string): AuthenticationRequestPayload {
    // We strip the uri scheme before passing it to the decode function
    return decodeUriAsJson(uri.replace(/^.*:\/\/\??/, '')) as AuthenticationRequestPayload;
  }

  /**
   * Create a signed SIOP request as JWT on RP side, typically you will want to use the createURI version!
   *
   * @param opts Request input data to build a SIOP Request as JWT
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT.
   *
   * Normally you will want to use the createURI version. That creates a URI that includes the JWT from this method in the URI
   * If you do use this method, you can call the wrapInUri afterwards to get the URI
   */
  static async createJWT(opts: AuthenticationRequestOpts): Promise<AuthenticationRequestWithJWT> {
    const siopRequestPayload = await createAuthenticationRequestPayload(opts);
    const { nonce, state } = siopRequestPayload;
    const jwt = await signDidJwtPayload(siopRequestPayload, opts);

    return {
      jwt,
      nonce,
      state,
      payload: siopRequestPayload,
      opts: opts,
    };
  }

  static async wrapAsURI(request: AuthenticationRequestWithJWT): Promise<AuthenticationRequestURI> {
    return await createURIFromJWT(request.opts, request.payload, request.jwt);
  }

  /**
   * Verifies a SIOP Request JWT on OP side
   *
   * @param jwt
   * @param opts
   */
  static async verifyJWT(jwt: string, opts: VerifyAuthenticationRequestOpts): Promise<VerifiedAuthenticationRequestWithJWT> {
    assertValidVerifyOpts(opts);
    if (!jwt) {
      throw new Error(SIOPErrors.NO_JWT);
    }

    const { header, payload } = parseJWT(jwt);
    assertValidRequestJWT(header, payload);

    const options = {
      audience: getAudience(jwt),
    };

    const verPayload = payload as AuthenticationRequestPayload;
    if (opts.nonce && verPayload.nonce !== opts.nonce) {
      throw new Error(`${SIOPErrors.BAD_NONCE} payload: ${payload.nonce}, supplied: ${opts.nonce}`);
    }

    await this.assertValidRegistration(verPayload, await AuthenticationRequest.getRemoteRegistrationObj(verPayload.registration_uri));

    const verifiedJWT = await verifyDidJWT(jwt, getResolver(opts.verification.resolveOpts), options);
    if (!verifiedJWT || !verifiedJWT.payload) {
      throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
    }
    const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(payload);
    return {
      ...verifiedJWT,
      verifyOpts: opts,
      presentationDefinitions,
      payload: verifiedJWT.payload as AuthenticationRequestPayload,
    };
  }

  static async assertValidRegistration(verPayload: AuthenticationRequestPayload, remoteRegObj: RPRegistrationMetadataPayload): Promise<void> {
    if (verPayload.registration_uri && verPayload.registration) {
      throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`);
    } else if (verPayload.registration_uri) {
      try {
        new URL(verPayload.registration_uri);
      } catch (e) {
        throw new Error(`${SIOPErrors.REG_PASS_BY_REFERENCE_INCORRECTLY}`);
      }
    }

    const regObj: RPRegistrationMetadataPayload = verPayload.registration_uri ? remoteRegObj : verPayload.registration;

    if (regObj && !validateRPRegistrationMetadata(regObj)) {
      throw new Error('Registration data validation error: ' + JSON.stringify(validateRPRegistrationMetadata.errors));
    } else if (regObj?.subject_syntax_types_supported && regObj.subject_syntax_types_supported.length == 0) {
      throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`);
    }
  }

  static async getRemoteRegistrationObj(registrationUri: string): Promise<RPRegistrationMetadataPayload> {
    let response: RPRegistrationMetadataPayload;
    if (registrationUri) {
      response = (await getWithUrl(registrationUri)) as unknown as RPRegistrationMetadataPayload;
    }

    return response;
  }
}

/***************************************
 *
 * Helper functions are down below
 *
 ***************************************/

/**
 * Creates an URI Request
 * @param requestOpts Options to define the Uri Request
 * @param requestPayload
 * @param jwt
 * @param requestPayload
 * @param jwt
 */
async function createURIFromJWT(
  requestOpts: AuthenticationRequestOpts,
  requestPayload: AuthenticationRequestPayload,
  jwt: string
): Promise<AuthenticationRequestURI> {
  const schema = 'openid://';
  // Only used to validate if it contains a definition
  await PresentationExchange.findValidPresentationDefinitions(requestPayload);
  const query = encodeJsonAsURI(requestPayload);

  await AuthenticationRequest.assertValidRegistration(
    requestPayload,
    await AuthenticationRequest.getRemoteRegistrationObj(requestPayload.registration_uri)
  );

  switch (requestOpts.requestBy?.type) {
    case PassBy.REFERENCE:
      return {
        encodedUri: `${schema}?${query}&request_uri=${encodeURIComponent(requestOpts.requestBy.referenceUri)}`,
        encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
        requestOpts,
        requestPayload,
        jwt,
      };
    case PassBy.VALUE:
      return {
        encodedUri: `${schema}?${query}&request=${jwt}`,
        encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
        requestOpts,
        requestPayload,
        jwt,
      };
  }
  throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
}

function assertValidRequestJWT(_header: JWTHeader, _payload: JWTPayload) {
  /*console.log(_header);
    console.log(_payload);*/
}

function assertValidVerifyOpts(opts: VerifyAuthenticationRequestOpts) {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
}

function assertValidRequestOpts(opts: AuthenticationRequestOpts) {
  if (!opts || !opts.redirectUri) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (!opts.requestBy) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  } else if (opts.requestBy.type !== PassBy.REFERENCE && opts.requestBy.type !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  } else if (opts.requestBy.type === PassBy.REFERENCE && !opts.requestBy.referenceUri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI);
  }
  assertValidRequestRegistrationOpts(opts.registration);
}

function createClaimsPayload(opts: ClaimOpts): ClaimPayload {
  if (!opts || !opts.presentationDefinitions || opts.presentationDefinitions.length == 0) {
    return undefined;
  }
  let vp_token: VpTokenClaimPayload;
  let id_token: IdTokenClaimPayload;

  opts.presentationDefinitions.forEach((def) => {
    switch (def.location) {
      case PresentationLocation.ID_TOKEN: {
        if (!id_token || !id_token.verifiable_presentations) {
          id_token = { verifiable_presentations: [{ presentation_definition: def.definition }] };
        } else {
          id_token.verifiable_presentations.push({ presentation_definition: def.definition });
        }
        return;
      }
      case PresentationLocation.VP_TOKEN: {
        if (vp_token) {
          // There can only be one definition in the vp_token according to the spec
          throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
        } else {
          vp_token = {
            //TODO: nonce should be initialized correctly
            nonce: 'NONCE_STRING',
            presentation_definition: def.definition,
            response_type: PresentationLocation.VP_TOKEN,
          };
        }
        return;
      }
    }
  });
  const payload: ClaimPayload = {
    id_token,
    vp_token,
  };
  return payload;
}

async function createAuthenticationRequestPayload(opts: AuthenticationRequestOpts): Promise<AuthenticationRequestPayload> {
  assertValidRequestOpts(opts);
  const state = getState(opts.state);
  const registration = await createRequestRegistration(opts.registration);
  const claims = createClaimsPayload(opts.claims);

  return {
    response_type: ResponseType.ID_TOKEN,
    scope: Scope.OPENID,
    client_id: opts.signatureType.did || opts.redirectUri, //todo: check whether we should include opts.redirectUri value here, or the whole of client_id to begin with
    redirect_uri: opts.redirectUri,
    iss: opts.signatureType.did,
    response_mode: opts.responseMode || ResponseMode.POST,
    response_context: opts.responseContext || ResponseContext.RP,
    nonce: getNonce(state, opts.nonce),
    state,
    ...registration.requestRegistrationPayload,
    claims,
  };
}
