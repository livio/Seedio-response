var _ = require('lodash'),
    async = require('async');

var config,
    log,
    debug;

var Response = function(_config, _log) {
  log = _log;
  debug = (_config && _config.server) ? _config.server.debug : false;
  config = _config;
};

/**
 * Format and send the server's current response value.
 * @param {function} viewHandler is middleware for handling any rendering logic. It takes in a function with (req, res, next)
 * @returns {Function}
 */
Response.prototype.responseHandler = function(viewHandler) {
  return function(req, res, next) {
    if(req.session) {
      req.session.returnTo = null;   // Clear returnTo when response is handled.
    }

    if(isApiPath(req.path) || !viewHandler) {
      if (!res || !res.locals || res.locals.data === undefined || res.locals.data === null) {
        log.warn('res.locals.data is not set. Assuming the endpoint was not handled and does not exist.');
        res.setError('API endpoint not found.', 404);
      } else {
        formatResponse(res.locals.data, req.user, (res.locals.sanitizeData !== false), function(err, responseObject) {
          if(err) {
            next(err);
          } else {
            res.status(200).json(formatResponseFlags(res.getFlags(), responseObject));
          }
        });
      }
    } else {
      viewHandler(req, res, next);
    }
  }
};

/**
 * Format and send the server's current error value.
 * @param {function} errorViewHandler is middleware for handling any rendering logic. It takes in a function with (req, res, next)
 * @returns {Function}
 */
Response.prototype.errorHandler = function(errorViewHandler) {
  return function (err, req, res, next) {
    if (!err.status || err.status == 500) {
      log.error(err);
    }

    if (isApiPath(req.path) || !viewHandler) {
      res.statusCode = err.status || 500;
      res.status(err.status || 500).json(formatResponseFlags(res.getFlags(), formatErrorResponse(err)));
      next();
    } else {
      errorViewHandler(err, req, res, next);
    }
  };
};

/**
 * Formats the standard response JSON using the passed in data.
 * @param v is the response value to format.
 * @param user is the requesting user object to be passed to the sanitize method.
 * @param {{Boolean}} isSanitize indicates whether or not to attempt to sanitize the response value.
 * @param cb is a callback method where an error or response object is returned.
 * @returns {{Object}} a server response object.
 */
function formatResponse(v, user, isSanitize, cb) {
  // Create the response object.
  var response = {};

  // Attempt to sanitize the data before sending it to the client.
  if(isSanitize) {
    sanitize(v, user, function(err, v) {
      if(err) {
        cb(err);
      } else {
        response.response = v;
        cb(undefined, response);
      }
    });
  } else {
    response.response = v;
    cb(undefined, response);
  }
}

var sanitize = function(v, user, cb) {
  var tasks = [];

  var type = getType(v);
  if (type === "array") {
    for (var i = v.length - 1; i >= 0; --i) {
      if (v[i] && v[i]["sanitize"]) {
        tasks.push(createSanitizeMethod(v[i], user));
      } else {
        return cb(undefined, v);
      }
    }
  } else if (type === "object" && v && v["sanitize"]) {
    tasks.push(createSanitizeMethod(v, user));
  } else {
    return cb(undefined, v);
  }

  async.parallel(tasks, function(err, results) {
    if(err) {
      cb(err);
    } else {
      if (type === "array") {
        cb(undefined, results);
      } else {
        cb(undefined, results[0]);
      }
    }
  });
};

var createSanitizeMethod = function(obj, user) {
  return function(cb) {
    obj.sanitize(user, cb);
  }
};

/**
 * Formats the standard error response JSON using the passed in data.
 * @param err is the server's error object to be returned.
 * @returns {{Object}} a server response object.
 */
function formatErrorResponse(err) {
  var response = {};

  response.error = {
    message: err.message
  };

  if(Response.debug) {
    response.error.stack = err.stack;
  }

  return response;
}

function formatResponseFlags(flags, obj) {
  obj = (obj) ? obj : {};

  for(var key in flags) {
    if(flags.hasOwnProperty(key)) {
      obj[key] = flags[key];
      switch(key) {
        case 'captchaRequired':
          obj['recaptchaClientKey'] = config.recaptcha.clientKey;
          break;

        default:
          // TODO: Currently unknown flags.
          log.trace("Unknown response flag: %s ", key);
          break;
      }

    }
  }


  return obj;
}

/**
 * Checks if the string path points to the API
 * @param path The string path. ie '/api/applications'
 * @returns {boolean} True if the request is being send to the API endpoints. Otherwise false.
 */
function isApiPath(path) {
  return path.toLowerCase().indexOf('/api') > -1
}

/**
 * Gets the response value's type.
 * @param v is the value to determine the type of.
 * @returns {string} a lowercase string description of the value type.  (e.g. array, boolean, object, etc.)
 */
var getType = function(v) {
  return ({}).toString.call(v).match(/\s([a-zA-Z]+)/)[1].toLowerCase()
};


/* **************************************
 * * Helper function that extends the express.response object to include a setData function.
 * **************************************/

/**
 * Adds setData(object) to the res object. Calling setData/setError will also call next.
 * @param req is the express request parameter.
 * @param res is the express response parameter.  The setData and setError methods will be added to this object.
 * @param next is the callback method.
 */
Response.prototype.addSetMethods = function (req, res, next) {
  res.setData = function (data, next) {
    res.locals.data = data;
    if(next) {
      return next();
    }
  };

  res.getData = function() {
    return res.locals.data
  };

  res.setFlags = function(flags) {
    return res.locals.flags = flags;
  };

  res.setFlag = function(flag, value) {
    if( ! res.locals.flags) {
      res.locals.flags = {};
    }

    return res.locals.flags[flag] = value;
  };

  res.getFlag = function(flag) {
    return (_.isObject(res.locals.flags)) ? res.locals.flags[flag] : undefined;
  };

  res.getFlags = function() {
    return res.locals.flags;
  };

  res.setError = function(locale, code) {
    return next(createError(req, locale, code));
  };

  res.setBadRequest = function(locale, responseData) {
    return next(createBadRequestError(req, locale));
  };

  res.setUnauthorized = function(locale) {
    return next(createUnauthorizedError(req, locale));
  };

  /**
   * 403 - Forbidden
   * Sent when an authenticated user does not have permission to access a specific resource.
   * @param locale is optional, it can be a locale key or a custom message.
   */
  res.setPermissionDenied = function(locale) {  //TODO: Change to setForbidden
    return next(createForbiddenError(req, locale));
  };

  res.setNotFound = function(locale) {
    return next(createNotFoundError(req, locale));
  };

  next();
};

var createError = function(req, locale, code) {
  var err = new Error(req.i18n.t(locale ||'server.error.generic') || locale);
  err.status = code || 500;
  return err;
};

var createBadRequestError = function(req, locale) {
  var err = new Error(req.i18n.t(locale ||'server.error.badRequest') || locale);
  err.status = 400;
  return err;
};

var createUnauthorizedError = function(req, locale) {
  var err = new Error(req.i18n.t(locale ||'server.error.unauthorized') || locale);
  err.status = 401;
  return err;
};

var createForbiddenError = function(req, locale) {
  var err = new Error(req.i18n.t(locale ||'server.error.forbidden') || locale);
  err.status = 403;
  return err;
};

var createNotFoundError = function(req, locale) {
  var err = new Error(req.i18n.t(locale ||'server.error.notFound') || locale);
  err.status = 404;
  return err;
};

var sanitizeRenderData = function(req, res, next) {
  var data = res.getData();
  if(_.isArray(data)) {
    formatResponse(data, req.user, (res.locals.sanitizeData !== false), function(err, responseObj) {
      if(err) {
        next(err);
      } else {
        data = responseObj.response;
        res.setData(data);
        next();
      }
    });
  } else if(_.isObject(data)) {
    data.populate('lastUpdatedBy', function(err, data) {
      if(err) {
        next(err);
      } else {
        formatResponse(data, req.user, (res.locals.sanitizeData !== false), function(err, responseObj) {
          if(err) {
            next(err);
          } else {
            data = responseObj.response;
            data.lastUpdatedBy = (data && data.lastUpdatedBy && data.lastUpdatedBy.username) ? data.lastUpdatedBy.username : req.i18n.t('server.user.unknown');
            res.setData(data);
            next();
          }
        });
      }
    });
  } else {
    next();
  }
};

Response.prototype.createBadRequestError = createBadRequestError;
Response.prototype.createUnauthorizedError = createUnauthorizedError;
Response.prototype.createForbiddenError = createForbiddenError;
Response.prototype.createNotFoundError = createNotFoundError;
Response.prototype.sanitizeRenderData = sanitizeRenderData;

exports = module.exports = Response;
exports = Response;