'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
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

  Logger.debug(entities);
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
      if (!result.body || result.body === null || !result.body.success || result.body.success != true) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        let validResults = [];
        
        Logger.trace({result}, "Logging lookup results");

        for (let i = 0; i < result.body.data.report.blacklists.engines_count; i++) {
          const engines = result.body.data.report.blacklists.engines[i];

          if (engines.detected === true) {
            validResults.push(engines);
          }
          Logger.trace({valid: validResults}, "logging blacklist stuff");
        }

        if (options.blocklistedOnly === true && validResults.length === 0) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: [],
              details: {
                totalResults: result.body,
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

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200 && body) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 404) {
    //Autofocus returns a 404 if indicator is not present in the DB.
    result = {
      entity,
      body: null
    };
  } else if (res.statusCode === 400) {
    result = {
      error: 'Bad Request',
      detail: body
    };
  } else if (res.statusCode === 429) {
    result = {
      error: 'Rate Limit Exceeded',
      detail: body
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
    (typeof options[optionName].value === 'string' &&
      options[optionName].value.length === 0)
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

  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  validateOptions: validateOptions,
  startup: startup
};
