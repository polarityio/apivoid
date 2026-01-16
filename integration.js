'use strict';

const request = require('postman-request');
const async = require('async');
const get = require('lodash.get');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;
const API_URL = 'https://api.apivoid.com/v2';

function startup(logger) {
  let defaults = { json: true };
  Logger = logger;

  requestWithDefaults = request.defaults(defaults);
}

const isLoopBackIp = (entity) => {
  return entity.startsWith('127');
};

const isLinkLocalAddress = (entity) => {
  return entity.startsWith('169');
};

const isPrivateIP = (entity) => {
  return entity.isPrivateIP === true;
};

const isValidIp = (entity) => {
  return !(isLoopBackIp(entity.value) || isLinkLocalAddress(entity.value) || isPrivateIP(entity));
};

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      headers: {
        'X-API-Key': options.apiKey,
        'Content-Type': 'application/json'
      },
      method: 'POST',
      json: true
    };

    if (entity.isIPv4 && isValidIp(entity)) {
      requestOptions.uri = `${API_URL}/ip-reputation`;
      requestOptions.body = {
        ip: entity.value
      };
    } else if (entity.isDomain) {
      requestOptions.uri = `${API_URL}/domain-reputation`;
      requestOptions.body = {
        host: entity.value
      };
    } else {
      lookupResults.push({
        entity,
        data: null
      });
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
      if (!result.body) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        const validResults = [];
        const unblockedEngines = [];
        Logger.trace({ result }, 'Logging lookup results');

        for (let i = 0; i < result.body.blacklists?.engines_count; i++) {
          const engine = result.body.blacklists?.engines[i];

          if (engine?.detected === true) {
            validResults.push(engine);
          } else {
            unblockedEngines.push(engine);
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
                detectedResults: validResults,
                unblockedEngines
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
  const categories = get(body, 'category', {});
  Object.keys(categories).forEach((key) => {
    if (categories[key]) {
      tags.push(key.replace('is_', '').replace(/_/g, ' '));
    }
  });
  return tags;
}

function getAnonymityTags(body) {
  const tags = [];

  const isProxy = get(body, 'anonymity.is_proxy', false);
  const isWebProxy = get(body, 'anonymity.is_webproxy', false);
  const isVPN = get(body, 'anonymity.is_vpn', false);
  const isHosting = get(body, 'anonymity.is_hosting', false);
  const isTor = get(body, 'anonymity.is_tor', false);

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
  tags.push(`Risk Score: ${get(body, 'risk_score.result', 'Not Available')}`);
  tags.push(
    `Detection Ratio: ${get(body, 'blacklists.detections')} / ${get(
      body,
      'blacklists.engines_count'
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
