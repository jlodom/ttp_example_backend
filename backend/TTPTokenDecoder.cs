using System;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Claims;

namespace backend {
	public class TTPTokenDecoder {
		public static JsonWebToken DecodeToken(String token, String pathJwks) {


			/* Get our basic objects from the Strings above. */
			String jwks = System.IO.File.ReadAllText(pathJwks);
			JsonWebKeySet exampleJWKS = new JsonWebKeySet(jwks);
			JsonWebKey exampleJWK = exampleJWKS.Keys.First();
			JsonWebToken exampleJWT = new JsonWebToken(token);

			/* Create RSA from Elements in JWK */
			RSAParameters rsap = new RSAParameters {
				Modulus = WebEncoders.Base64UrlDecode(exampleJWK.N),
				Exponent = WebEncoders.Base64UrlDecode(exampleJWK.E),
				D = WebEncoders.Base64UrlDecode(exampleJWK.D),
				P = WebEncoders.Base64UrlDecode(exampleJWK.P),
				Q = WebEncoders.Base64UrlDecode(exampleJWK.Q),
				DP = WebEncoders.Base64UrlDecode(exampleJWK.DP),
				DQ = WebEncoders.Base64UrlDecode(exampleJWK.DQ),
				InverseQ = WebEncoders.Base64UrlDecode(exampleJWK.QI),
			};
			RSA rsa = RSA.Create();
			rsa.ImportParameters(rsap);
			RsaSecurityKey rsakey = new RsaSecurityKey(rsa);
			rsakey.KeyId = exampleJWK.KeyId;
			rsa.KeySize = exampleJWK.KeySize;

			/* Create a JSON Token Handler and Try Decrypting the Token */
			JsonWebTokenHandler exampleHandler = new JsonWebTokenHandler();
			TokenValidationParameters validationParameters = new TokenValidationParameters {
				ValidateAudience = false,
				ValidateIssuer = false,
				RequireSignedTokens = false, /* Have also tried with this set to True */
				TokenDecryptionKey = rsakey,
			};

			String clearTokenString = exampleHandler.DecryptToken(exampleJWT, validationParameters);

			JsonWebToken DecryptedJWT = new JsonWebToken(clearTokenString);
			return DecryptedJWT;
		}

		/* Example for Getting a Claim (Attribute) Back from a Token) */
		public static String GetEmailFromToken(JsonWebToken decodedToken) {
			String stringReturn = "dot@dotat.at";
			Claim returnClaim;
			if(decodedToken.TryGetClaim("email", out returnClaim)) {
				stringReturn = returnClaim.Value;
			}
			return stringReturn;

		}

		/* Convenience Routine */
		public static String GetEmailFromEncryptedToken(String encToken, String pathJWKSPassThrough) {
			return GetEmailFromToken(DecodeToken(encToken, pathJWKSPassThrough));
		}

	}
}
