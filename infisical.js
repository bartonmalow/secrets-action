const axios = require('axios');
const core = require('@actions/core');
const querystring = require('querystring');

const UALogin = async ({ domain, clientId, clientSecret }) => {
  const loginData = {
    clientId,
    clientSecret,
  };

  try {
    core.debug('Logging in to Infisical with Universal Authentication');
    core.debug(`Domain: ${domain}`);
    // Don't log sensitive data, but log the structure
    core.debug('Login Data structure:', Object.keys(loginData));
    
    const response = await axios({
      method: 'post',
      url: `${domain}/api/v1/auth/universal-auth/login`,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: loginData,
      // Add timeout and additional debugging
      timeout: 10000,
      validateStatus: (status) => {
        core.debug(`Response status: ${status}`);
        return status >= 200 && status < 300;
      }
    });

    if (!response?.data?.token) {
      throw new Error('Invalid response format: missing token');
    }

    return response.data.token;
  } catch (error) {
    core.debug(`Error details: ${error.response?.data || error.message}`);
    throw new Error(`Universal Auth login failed: ${error.message}`);
  }
};

const oidcLogin = async ({ identityId, domain, oidcAudience }) => {
  const idToken = await core.getIDToken(oidcAudience);
  core.debug('Logging in to Infisical with OIDC Authentication');
  const loginData = querystring.stringify({
    identityId,
    jwt: idToken,
  });

  try {
    const response = await axios({
      method: 'post',
      url: `${domain}/api/v1/auth/oidc-auth/login`,
      headers: {
        'Content-Type': 'application/json',
      },
      data: loginData,
    });
    core.debug('Successfully logged in to Infisical with OIDC Authentication');
    return response.data.accessToken;
  } catch (err) {
    core.error('Error:', err.message);
    throw err;
  }
};

const getRawSecrets = async ({
  domain,
  envSlug,
  infisicalToken,
  projectSlug,
  secretPath,
  shouldIncludeImports,
  shouldRecurse,
}) => {
  try {
    core.debug('Fetching secrets from Infisical');
    if (!domain || !infisicalToken || !projectSlug) {
      throw new Error('Missing required parameters: domain, infisicalToken, or projectSlug');
    }

    const apiDomain = domain.startsWith('http') ? domain : `https://${domain}`;

    core.debug(`Making request to ${apiDomain}/api/v3/secrets/raw`);

    const response = await axios({
      method: 'get',
      url: `${apiDomain}/api/v3/secrets/raw`,
      params: {
        secretPath,
        environment: envSlug,
        include_imports: shouldIncludeImports,
        recursive: shouldRecurse,
        workspaceSlug: projectSlug,
        expandSecretReferences: true,
      },
      timeout: 10000,
      headers: {
        Authorization: `Bearer ${infisicalToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response?.data?.secrets) {
      throw new Error(
        `Invalid response format from Infisical API: ${JSON.stringify(response.data)}`
      );
    }

    const keyValueSecrets = {};

    // Process main secrets
    response.data.secrets.forEach((secret) => {
      if (secret.secretKey && secret.secretValue !== undefined) {
        keyValueSecrets[secret.secretKey] = secret.secretValue;
      }
    });

    // Process imported secrets if they exist
    if (response.data.imports && Array.isArray(response.data.imports)) {
      for (let i = response.data.imports.length - 1; i >= 0; i--) {
        const importedSecrets = response.data.imports[i].secrets || [];
        importedSecrets.forEach((secret) => {
          if (
            secret.secretKey &&
            secret.secretValue !== undefined &&
            !Object.prototype.hasOwnProperty.call(keyValueSecrets, secret.secretKey)
          ) {
            keyValueSecrets[secret.secretKey] = secret.secretValue;
          }
        });
      }
    }

    return keyValueSecrets;
  } catch (err) {
    core.error('Error fetching secrets:', err.message);
    throw err;
  }
};

module.exports = {
  UALogin,
  getRawSecrets,
  oidcLogin,
};
