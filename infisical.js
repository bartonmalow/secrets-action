const axios = require('axios');
const core = require('@actions/core');
const querystring = require('querystring');

const UALogin = async ({ clientId, clientSecret, domain }) => {
  const loginData = {
    clientId,
    clientSecret,
  };

  try {
    core.debug('Logging in to Infisical with Universal Authentication');
    core.debug(`Domain: ${domain}`);
    
    // Ensure domain is properly formatted
    const apiDomain = domain.startsWith('http') ? domain : `https://${domain}`;
    const loginUrl = `${apiDomain}/api/v1/auth/universal-auth/login`;
    
    core.debug(`Making request to: ${loginUrl}`);
    
    const response = await axios({
      method: 'post',
      url: loginUrl,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      data: loginData,
    });
    
    if (!response?.data?.accessToken) {
      throw new Error('Invalid response format: missing access token');
    }

    core.debug('Successfully logged in to Infisical with Universal Authentication');
    return response.data.accessToken;
  } catch (err) {
    core.debug(`Full error: ${err.response?.data ? JSON.stringify(err.response.data) : err.message}`);
    throw err;
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
