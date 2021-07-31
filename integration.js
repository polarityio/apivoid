'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const get = require('lodash.get');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      json: true
    };

    if (entity.isIPv4) {
      (requestOptions.uri = `${options.url}/iprep/v1/pay-as-you-go/`),
        (requestOptions.qs = {
          key: options.apiKey,
          ip: entity.value
        });
    } else if (entity.isDomain) {
      (requestOptions.uri = `${options.url}/domainbl/v1/pay-as-you-go/`),
        (requestOptions.qs = {
          key: options.apiKey,
          host: entity.value
        });
    } else {
      return;
    }

    Logger.trace({ requestOptions }, 'Request Options');

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          done(processedResult);
          return;
        }

        done(null, processedResult);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (
        !result.body ||
        result.body === null ||
        !result.body.success ||
        result.body.success != true
      ) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        let validResults = [];

        Logger.trace({ result }, 'Logging lookup results');

        for (let i = 0; i < result.body.data.report.blacklists.engines_count; i++) {
          const engines = result.body.data.report.blacklists.engines[i];

          if (engines.detected === true) {
            validResults.push(engines);
          }
          Logger.trace({ valid: validResults }, 'logging blacklist stuff');
        }

        if (options.blocklistedOnly === true && validResults.length === 0) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          const anonymityTags = getAnonymityTags(result.body);
          const categoryTags = getCategoryTags(result.body);
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: getSummaryTags(result.body).concat(anonymityTags).concat(categoryTags),
              details: {
                totalResults: result.body,
                anonymityTags,
                categoryTags,
                detectedResults: validResults
              }
            }
          });
        }
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function getCategoryTags(body) {
  const tags = [];

  const isFreeHosting = get(body, 'data.report.category.is_free_hosting', false);
  const isAnonymizer = get(body, 'data.report.category.is_anonymizer', false);
  const isUrlShortener = get(body, 'data.report.category.is_url_shortener', false);
  const isFreeDynamicDns = get(body, 'data.report.category.is_free_dynamic_dns', false);

  if (isFreeHosting) {
    tags.push('Free Hosting');
  }
  if (isAnonymizer) {
    tags.push('Anonymizer');
  }

  if (isUrlShortener) {
    tags.push('URL Shortener');
  }

  if (isFreeDynamicDns) {
    tags.push('Free Dynamic DNS');
  }

  return tags;
}

function getAnonymityTags(body) {
  const tags = [];

  const isProxy = get(body, 'data.report.anonymity.is_proxy', false);
  const isWebProxy = get(body, 'data.report.anonymity.is_webproxy', false);
  const isVPN = get(body, 'data.report.anonymity.is_vpn', false);
  const isHosting = get(body, 'data.report.anonymity.is_hosting', false);
  const isTor = get(body, 'data.report.anonymity.is_tor', false);

  if (isProxy) {
    tags.push('Proxy');
  }
  if (isWebProxy) {
    tags.push('Web Proxy');
  }

  if (isVPN) {
    tags.push('VPN');
  }

  if (isHosting) {
    tags.push('Hosting');
  }

  if (isTor) {
    tags.push('Tor');
  }

  return tags;
}

function getSummaryTags(body) {
  const tags = [];
  tags.push(`Risk Score: ${get(body, 'data.report.risk_score.result', 'Not Available')}`);
  tags.push(
    `Detection Ratio: ${get(body, 'data.report.blacklists.detections')} / ${get(
      body,
      'data.report.blacklists.engines_count'
    )}`
  );

  return tags;
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  Logger.trace({ body, status: res.statusCode }, 'handleRestError');

  if (res.statusCode === 200 && body && body.error) {
    result = {
      detail: body.error,
      error: body
    };
  } else if (res.statusCode === 200 && body) {
    result = {
      entity,
      body
    };
  } else {
    result = {
      error: 'Unexpected Error',
      statusCode: res ? res.statusCode : 'Unknown',
      detail: 'An unexpected error occurred'
    };
  }

  return result;
}

function validateOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateOption(errors, options, 'apiKey', 'You must provide a valid API Key.');

  validateOption(errors, options, 'url', 'You must provide a valid APIVoid API url.');

  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  validateOptions: validateOptions,
  startup: startup
};
