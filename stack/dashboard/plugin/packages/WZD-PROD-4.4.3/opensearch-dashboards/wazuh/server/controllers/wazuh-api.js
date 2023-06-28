"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhApiCtrl = void 0;

var _errorResponse = require("../lib/error-response");

var _json2csv = require("json2csv");

var _logger = require("../lib/logger");

var _csvKeyEquivalence = require("../../common/csv-key-equivalence");

var _apiErrorsEquivalence = require("../lib/api-errors-equivalence");

var _endpoints = _interopRequireDefault(require("../../common/api-info/endpoints"));

var _constants = require("../../common/constants");

var _settings = require("../../common/services/settings");

var _queue = require("../start/queue");

var _fs = _interopRequireDefault(require("fs"));

var _manageHosts = require("../lib/manage-hosts");

var _updateRegistry = require("../lib/update-registry");

var _jwtDecode = _interopRequireDefault(require("jwt-decode"));

var _cacheApiUserHasRunAs = require("../lib/cache-api-user-has-run-as");

var _cookie = require("../lib/cookie");

var _getConfiguration = require("../lib/get-configuration");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class WazuhApiCtrl {
  constructor() {
    _defineProperty(this, "manageHosts", void 0);

    _defineProperty(this, "updateRegistry", void 0);

    this.manageHosts = new _manageHosts.ManageHosts();
    this.updateRegistry = new _updateRegistry.UpdateRegistry();
  }

  async getToken(context, request, response) {
    try {
      const {
        force,
        idHost
      } = request.body;
      const {
        username
      } = await context.wazuh.security.getCurrentUser(request, context);

      if (!force && request.headers.cookie && username === (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-user') && idHost === (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api')) {
        const wzToken = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

        if (wzToken) {
          try {
            // if the current token is not a valid jwt token we ask for a new one
            const decodedToken = (0, _jwtDecode.default)(wzToken);
            const expirationTime = decodedToken.exp - Date.now() / 1000;

            if (wzToken && expirationTime > 0) {
              return response.ok({
                body: {
                  token: wzToken
                }
              });
            }
          } catch (error) {
            (0, _logger.log)('wazuh-api:getToken', error.message || error);
          }
        }
      }

      let token;

      if ((await _cacheApiUserHasRunAs.APIUserAllowRunAs.canUse(idHost)) == _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ENABLED) {
        token = await context.wazuh.api.client.asCurrentUser.authenticate(idHost);
      } else {
        token = await context.wazuh.api.client.asInternalUser.authenticate(idHost);
      }

      ;
      let textSecure = '';

      if (context.wazuh.server.info.protocol === 'https') {
        textSecure = ';Secure';
      }

      return response.ok({
        headers: {
          'set-cookie': [`wz-token=${token};Path=/;HttpOnly${textSecure}`, `wz-user=${username};Path=/;HttpOnly${textSecure}`, `wz-api=${idHost};Path=/;HttpOnly`]
        },
        body: {
          token
        }
      });
    } catch (error) {
      var _error$response;

      const errorMessage = ((error.response || {}).data || {}).detail || error.message || error;
      (0, _logger.log)('wazuh-api:getToken', errorMessage);
      return (0, _errorResponse.ErrorResponse)(`Error getting the authorization token: ${errorMessage}`, 3000, (error === null || error === void 0 ? void 0 : (_error$response = error.response) === null || _error$response === void 0 ? void 0 : _error$response.status) || _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * Returns if the wazuh-api configuration is working
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkStoredAPI(context, request, response) {
    try {
      // Get config from wazuh.yml
      const id = request.body.id;
      const api = await this.manageHosts.getHostById(id); // Check Manage Hosts

      if (!Object.keys(api).length) {
        throw new Error('Could not find Wazuh API entry on wazuh.yml');
      }

      (0, _logger.log)('wazuh-api:checkStoredAPI', `${id} exists`, 'debug'); // Fetch needed information about the cluster and the manager itself

      const responseManagerInfo = await context.wazuh.api.client.asInternalUser.request('get', `/manager/info`, {}, {
        apiHostID: id,
        forceRefresh: true
      }); // Look for socket-related errors

      if (this.checkResponseIsDown(responseManagerInfo)) {
        return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${responseManagerInfo.data.detail || 'Wazuh not ready yet'}`, 3099, _constants.HTTP_STATUS_CODES.SERVICE_UNAVAILABLE, response);
      } // If we have a valid response from the Wazuh API


      if (responseManagerInfo.status === _constants.HTTP_STATUS_CODES.OK && responseManagerInfo.data) {
        // Clear and update cluster information before being sent back to frontend
        delete api.cluster_info;
        const responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: {
            agents_list: '000'
          }
        }, {
          apiHostID: id
        });

        if (responseAgents.status === _constants.HTTP_STATUS_CODES.OK) {
          const managerName = responseAgents.data.data.affected_items[0].manager;
          const responseClusterStatus = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/status`, {}, {
            apiHostID: id
          });

          if (responseClusterStatus.status === _constants.HTTP_STATUS_CODES.OK) {
            if (responseClusterStatus.data.data.enabled === 'yes') {
              const responseClusterLocalInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
                apiHostID: id
              });

              if (responseClusterLocalInfo.status === _constants.HTTP_STATUS_CODES.OK) {
                const clusterEnabled = responseClusterStatus.data.data.enabled === 'yes';
                api.cluster_info = {
                  status: clusterEnabled ? 'enabled' : 'disabled',
                  manager: managerName,
                  node: responseClusterLocalInfo.data.data.affected_items[0].node,
                  cluster: clusterEnabled ? responseClusterLocalInfo.data.data.affected_items[0].cluster : 'Disabled'
                };
              }
            } else {
              // Cluster mode is not active
              api.cluster_info = {
                status: 'disabled',
                manager: managerName,
                cluster: 'Disabled'
              };
            }
          } else {
            // Cluster mode is not active
            api.cluster_info = {
              status: 'disabled',
              manager: managerName,
              cluster: 'Disabled'
            };
          }

          if (api.cluster_info) {
            // Update cluster information in the wazuh-registry.json
            await this.updateRegistry.updateClusterInfo(id, api.cluster_info); // Hide Wazuh API secret, username, password

            const copied = { ...api
            };
            copied.secret = '****';
            copied.password = '****';
            return response.ok({
              body: {
                statusCode: _constants.HTTP_STATUS_CODES.OK,
                data: copied,
                idChanged: request.body.idChanged || null
              }
            });
          }
        }
      } // If we have an invalid response from the Wazuh API


      throw new Error(responseManagerInfo.data.detail || `${api.url}:${api.port} is unreachable`);
    } catch (error) {
      if (error.code === 'EPROTO') {
        return response.ok({
          body: {
            statusCode: _constants.HTTP_STATUS_CODES.OK,
            data: {
              apiIsDown: true
            }
          }
        });
      } else if (error.code === 'ECONNREFUSED') {
        return response.ok({
          body: {
            statusCode: _constants.HTTP_STATUS_CODES.OK,
            data: {
              apiIsDown: true
            }
          }
        });
      } else {
        var _error$response3;

        try {
          const apis = await this.manageHosts.getHosts();

          for (const api of apis) {
            try {
              const id = Object.keys(api)[0];
              const responseManagerInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/manager/info`, {}, {
                apiHostID: id
              });

              if (this.checkResponseIsDown(responseManagerInfo)) {
                return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${response.data.detail || 'Wazuh not ready yet'}`, 3099, _constants.HTTP_STATUS_CODES.SERVICE_UNAVAILABLE, response);
              }

              if (responseManagerInfo.status === _constants.HTTP_STATUS_CODES.OK) {
                request.body.id = id;
                request.body.idChanged = id;
                return await this.checkStoredAPI(context, request, response);
              }
            } catch (error) {} // eslint-disable-line

          }
        } catch (error) {
          var _error$response2;

          (0, _logger.log)('wazuh-api:checkStoredAPI', error.message || error);
          return (0, _errorResponse.ErrorResponse)(error.message || error, 3020, (error === null || error === void 0 ? void 0 : (_error$response2 = error.response) === null || _error$response2 === void 0 ? void 0 : _error$response2.status) || _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
        }

        (0, _logger.log)('wazuh-api:checkStoredAPI', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 3002, (error === null || error === void 0 ? void 0 : (_error$response3 = error.response) === null || _error$response3 === void 0 ? void 0 : _error$response3.status) || _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
      }
    }
  }
  /**
   * This perfoms a validation of API params
   * @param {Object} body API params
   */


  validateCheckApiParams(body) {
    if (!('username' in body)) {
      return 'Missing param: API USERNAME';
    }

    if (!('password' in body) && !('id' in body)) {
      return 'Missing param: API PASSWORD';
    }

    if (!('url' in body)) {
      return 'Missing param: API URL';
    }

    if (!('port' in body)) {
      return 'Missing param: API PORT';
    }

    if (!body.url.includes('https://') && !body.url.includes('http://')) {
      return 'protocol_error';
    }

    return false;
  }
  /**
   * This check the wazuh-api configuration received in the POST body will work
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkAPI(context, request, response) {
    try {
      let apiAvailable = null; // const notValid = this.validateCheckApiParams(request.body);
      // if (notValid) return ErrorResponse(notValid, 3003, HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);

      (0, _logger.log)('wazuh-api:checkAPI', `${request.body.id} is valid`, 'debug'); // Check if a Wazuh API id is given (already stored API)

      const data = await this.manageHosts.getHostById(request.body.id);

      if (data) {
        apiAvailable = data;
      } else {
        (0, _logger.log)('wazuh-api:checkAPI', `API ${request.body.id} not found`);
        return (0, _errorResponse.ErrorResponse)(`The API ${request.body.id} was not found`, 3029, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
      }

      const options = {
        apiHostID: request.body.id
      };

      if (request.body.forceRefresh) {
        options["forceRefresh"] = request.body.forceRefresh;
      }

      let responseManagerInfo;

      try {
        responseManagerInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/manager/info`, {}, options);
      } catch (error) {
        var _error$response4, _error$response4$data, _error$response5;

        return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${((_error$response4 = error.response) === null || _error$response4 === void 0 ? void 0 : (_error$response4$data = _error$response4.data) === null || _error$response4$data === void 0 ? void 0 : _error$response4$data.detail) || 'Wazuh not ready yet'}`, 3099, (error === null || error === void 0 ? void 0 : (_error$response5 = error.response) === null || _error$response5 === void 0 ? void 0 : _error$response5.status) || _constants.HTTP_STATUS_CODES.SERVICE_UNAVAILABLE, response);
      }

      (0, _logger.log)('wazuh-api:checkAPI', `${request.body.id} credentials are valid`, 'debug');

      if (responseManagerInfo.status === _constants.HTTP_STATUS_CODES.OK && responseManagerInfo.data) {
        let responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: {
            agents_list: '000'
          }
        }, {
          apiHostID: request.body.id
        });

        if (responseAgents.status === _constants.HTTP_STATUS_CODES.OK) {
          const managerName = responseAgents.data.data.affected_items[0].manager;
          let responseCluster = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/status`, {}, {
            apiHostID: request.body.id
          }); // Check the run_as for the API user and update it

          let apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ALL_DISABLED;
          const responseApiUserAllowRunAs = await context.wazuh.api.client.asInternalUser.request('GET', `/security/users/me`, {}, {
            apiHostID: request.body.id
          });

          if (responseApiUserAllowRunAs.status === _constants.HTTP_STATUS_CODES.OK) {
            const allow_run_as = responseApiUserAllowRunAs.data.data.affected_items[0].allow_run_as;
            if (allow_run_as && apiAvailable && apiAvailable.run_as) // HOST AND USER ENABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ENABLED;else if (!allow_run_as && apiAvailable && apiAvailable.run_as) // HOST ENABLED AND USER DISABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.USER_NOT_ALLOWED;else if (allow_run_as && (!apiAvailable || !apiAvailable.run_as)) // USER ENABLED AND HOST DISABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.HOST_DISABLED;else if (!allow_run_as && (!apiAvailable || !apiAvailable.run_as)) // HOST AND USER DISABLED
              apiUserAllowRunAs = _cacheApiUserHasRunAs.API_USER_STATUS_RUN_AS.ALL_DISABLED;
          }

          _cacheApiUserHasRunAs.CacheInMemoryAPIUserAllowRunAs.set(request.body.id, apiAvailable.username, apiUserAllowRunAs);

          if (responseCluster.status === _constants.HTTP_STATUS_CODES.OK) {
            (0, _logger.log)('wazuh-api:checkStoredAPI', `Wazuh API response is valid`, 'debug');

            if (responseCluster.data.data.enabled === 'yes') {
              // If cluster mode is active
              let responseClusterLocal = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
                apiHostID: request.body.id
              });

              if (responseClusterLocal.status === _constants.HTTP_STATUS_CODES.OK) {
                return response.ok({
                  body: {
                    manager: managerName,
                    node: responseClusterLocal.data.data.affected_items[0].node,
                    cluster: responseClusterLocal.data.data.affected_items[0].cluster,
                    status: 'enabled',
                    allow_run_as: apiUserAllowRunAs
                  }
                });
              }
            } else {
              // Cluster mode is not active
              return response.ok({
                body: {
                  manager: managerName,
                  cluster: 'Disabled',
                  status: 'disabled',
                  allow_run_as: apiUserAllowRunAs
                }
              });
            }
          }
        }
      }
    } catch (error) {
      var _error$response6;

      (0, _logger.log)('wazuh-api:checkAPI', error.message || error);

      if (error && error.response && error.response.status === _constants.HTTP_STATUS_CODES.UNAUTHORIZED) {
        return (0, _errorResponse.ErrorResponse)(`Unathorized. Please check API credentials. ${error.response.data.message}`, _constants.HTTP_STATUS_CODES.UNAUTHORIZED, _constants.HTTP_STATUS_CODES.UNAUTHORIZED, response);
      }

      if (error && error.response && error.response.data && error.response.data.detail) {
        return (0, _errorResponse.ErrorResponse)(error.response.data.detail, error.response.status || _constants.HTTP_STATUS_CODES.SERVICE_UNAVAILABLE, error.response.status || _constants.HTTP_STATUS_CODES.SERVICE_UNAVAILABLE, response);
      }

      if (error.code === 'EPROTO') {
        return (0, _errorResponse.ErrorResponse)('Wrong protocol being used to connect to the Wazuh API', 3005, _constants.HTTP_STATUS_CODES.BAD_REQUEST, response);
      }

      return (0, _errorResponse.ErrorResponse)(error.message || error, 3005, (error === null || error === void 0 ? void 0 : (_error$response6 = error.response) === null || _error$response6 === void 0 ? void 0 : _error$response6.status) || _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }

  checkResponseIsDown(response) {
    if (response.status !== _constants.HTTP_STATUS_CODES.OK) {
      // Avoid "Error communicating with socket" like errors
      const socketErrorCodes = [1013, 1014, 1017, 1018, 1019];
      const status = (response.data || {}).status || 1;
      const isDown = socketErrorCodes.includes(status);
      isDown && (0, _logger.log)('wazuh-api:makeRequest', 'Wazuh API is online but Wazuh is not ready yet');
      return isDown;
    }

    return false;
  }
  /**
   * Check main Wazuh daemons status
   * @param {*} context Endpoint context
   * @param {*} api API entry stored in .wazuh
   * @param {*} path Optional. Wazuh API target path.
   */


  async checkDaemons(context, api, path) {
    try {
      const response = await context.wazuh.api.client.asInternalUser.request('GET', '/manager/status', {}, {
        apiHostID: api.id
      });
      const daemons = ((((response || {}).data || {}).data || {}).affected_items || [])[0] || {};
      const isCluster = ((api || {}).cluster_info || {}).status === 'enabled' && typeof daemons['wazuh-clusterd'] !== 'undefined';
      const wazuhdbExists = typeof daemons['wazuh-db'] !== 'undefined';
      const execd = daemons['wazuh-execd'] === 'running';
      const modulesd = daemons['wazuh-modulesd'] === 'running';
      const wazuhdb = wazuhdbExists ? daemons['wazuh-db'] === 'running' : true;
      const clusterd = isCluster ? daemons['wazuh-clusterd'] === 'running' : true;
      const isValid = execd && modulesd && wazuhdb && clusterd;
      isValid && (0, _logger.log)('wazuh-api:checkDaemons', `Wazuh is ready`, 'debug');

      if (path === '/ping') {
        return {
          isValid
        };
      }

      if (!isValid) {
        throw new Error('Wazuh not ready yet');
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:checkDaemons', error.message || error);
      return Promise.reject(error);
    }
  }

  sleep(timeMs) {
    // eslint-disable-next-line
    return new Promise((resolve, reject) => {
      setTimeout(resolve, timeMs);
    });
  }
  /**
   * Helper method for Dev Tools.
   * https://documentation.wazuh.com/current/user-manual/api/reference.html
   * Depending on the method and the path some parameters should be an array or not.
   * Since we allow the user to write the request using both comma-separated and array as well,
   * we need to check if it should be transformed or not.
   * @param {*} method The request method
   * @param {*} path The Wazuh API path
   */


  shouldKeepArrayAsIt(method, path) {
    // Methods that we must respect a do not transform them
    const isAgentsRestart = method === 'POST' && path === '/agents/restart';
    const isActiveResponse = method === 'PUT' && path.startsWith('/active-response');
    const isAddingAgentsToGroup = method === 'POST' && path.startsWith('/agents/group/'); // Returns true only if one of the above conditions is true

    return isAgentsRestart || isActiveResponse || isAddingAgentsToGroup;
  }
  /**
   * This performs a request over Wazuh API and returns its response
   * @param {String} method Method: GET, PUT, POST, DELETE
   * @param {String} path API route
   * @param {Object} data data and params to perform the request
   * @param {String} id API id
   * @param {Object} response
   * @returns {Object} API response or ErrorResponse
   */


  async makeRequest(context, method, path, data, id, response) {
    const devTools = !!(data || {}).devTools;

    try {
      const api = await this.manageHosts.getHostById(id);

      if (devTools) {
        delete data.devTools;
      }

      if (!Object.keys(api).length) {
        (0, _logger.log)('wazuh-api:makeRequest', 'Could not get host credentials'); //Can not get credentials from wazuh-hosts

        return (0, _errorResponse.ErrorResponse)('Could not get host credentials', 3011, _constants.HTTP_STATUS_CODES.NOT_FOUND, response);
      }

      if (!data) {
        data = {};
      }

      ;

      if (!data.headers) {
        data.headers = {};
      }

      ;
      const options = {
        apiHostID: id
      }; // Set content type application/xml if needed

      if (typeof (data || {}).body === 'string' && (data || {}).origin === 'xmleditor') {
        data.headers['content-type'] = 'application/xml';
        delete data.origin;
      }

      if (typeof (data || {}).body === 'string' && (data || {}).origin === 'json') {
        data.headers['content-type'] = 'application/json';
        delete data.origin;
      }

      if (typeof (data || {}).body === 'string' && (data || {}).origin === 'raw') {
        data.headers['content-type'] = 'application/octet-stream';
        delete data.origin;
      }

      const delay = (data || {}).delay || 0;

      if (delay) {
        (0, _queue.addJobToQueue)({
          startAt: new Date(Date.now() + delay),
          run: async () => {
            try {
              await context.wazuh.api.client.asCurrentUser.request(method, path, data, options);
            } catch (error) {
              (0, _logger.log)('queue:delayApiRequest', `An error ocurred in the delayed request: "${method} ${path}": ${error.message || error}`);
            }

            ;
          }
        });
        return response.ok({
          body: {
            error: 0,
            message: 'Success'
          }
        });
      }

      if (path === '/ping') {
        try {
          const check = await this.checkDaemons(context, api, path);
          return check;
        } catch (error) {
          const isDown = (error || {}).code === 'ECONNREFUSED';

          if (!isDown) {
            (0, _logger.log)('wazuh-api:makeRequest', 'Wazuh API is online but Wazuh is not ready yet');
            return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${error.message || 'Wazuh not ready yet'}`, 3099, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
          }
        }
      }

      (0, _logger.log)('wazuh-api:makeRequest', `${method} ${path}`, 'debug'); // Extract keys from parameters

      const dataProperties = Object.keys(data); // Transform arrays into comma-separated string if applicable.
      // The reason is that we are accepting arrays for comma-separated
      // parameters in the Dev Tools

      if (!this.shouldKeepArrayAsIt(method, path)) {
        for (const key of dataProperties) {
          if (Array.isArray(data[key])) {
            data[key] = data[key].join();
          }
        }
      }

      const responseToken = await context.wazuh.api.client.asCurrentUser.request(method, path, data, options);
      const responseIsDown = this.checkResponseIsDown(responseToken);

      if (responseIsDown) {
        return (0, _errorResponse.ErrorResponse)(`ERROR3099 - ${response.body.message || 'Wazuh not ready yet'}`, 3099, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
      }

      let responseBody = (responseToken || {}).data || {};

      if (!responseBody) {
        responseBody = typeof responseBody === 'string' && path.includes('/files') && method === 'GET' ? ' ' : false;
        response.data = responseBody;
      }

      const responseError = response.status !== _constants.HTTP_STATUS_CODES.OK ? response.status : false;

      if (!responseError && responseBody) {
        //cleanKeys(response);
        return response.ok({
          body: responseToken.data
        });
      }

      if (responseError && devTools) {
        return response.ok({
          body: response.data
        });
      }

      throw responseError && responseBody.detail ? {
        message: responseBody.detail,
        code: responseError
      } : new Error('Unexpected error fetching data from the Wazuh API');
    } catch (error) {
      if (error && error.response && error.response.status === _constants.HTTP_STATUS_CODES.UNAUTHORIZED) {
        return (0, _errorResponse.ErrorResponse)(error.message || error, error.code ? `Wazuh API error: ${error.code}` : 3013, _constants.HTTP_STATUS_CODES.UNAUTHORIZED, response);
      }

      const errorMsg = (error.response || {}).data || error.message;
      (0, _logger.log)('wazuh-api:makeRequest', errorMsg || error);

      if (devTools) {
        return response.ok({
          body: {
            error: '3013',
            message: errorMsg || error
          }
        });
      } else {
        if ((error || {}).code && _apiErrorsEquivalence.ApiErrorEquivalence[error.code]) {
          error.message = _apiErrorsEquivalence.ApiErrorEquivalence[error.code];
        }

        return (0, _errorResponse.ErrorResponse)(errorMsg.detail || error, error.code ? `Wazuh API error: ${error.code}` : 3013, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
      }
    }
  }
  /**
   * This make a request to API
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} api response or ErrorResponse
   */


  requestApi(context, request, response) {
    const idApi = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

    if (idApi !== request.body.id) {
      // if the current token belongs to a different API id, we relogin to obtain a new token
      return (0, _errorResponse.ErrorResponse)('status code 401', _constants.HTTP_STATUS_CODES.UNAUTHORIZED, _constants.HTTP_STATUS_CODES.UNAUTHORIZED, response);
    }

    if (!request.body.method) {
      return (0, _errorResponse.ErrorResponse)('Missing param: method', 3015, _constants.HTTP_STATUS_CODES.BAD_REQUEST, response);
    } else if (!request.body.method.match(/^(?:GET|PUT|POST|DELETE)$/)) {
      (0, _logger.log)('wazuh-api:makeRequest', 'Request method is not valid.'); //Method is not a valid HTTP request method

      return (0, _errorResponse.ErrorResponse)('Request method is not valid.', 3015, _constants.HTTP_STATUS_CODES.BAD_REQUEST, response);
    } else if (!request.body.path) {
      return (0, _errorResponse.ErrorResponse)('Missing param: path', 3016, _constants.HTTP_STATUS_CODES.BAD_REQUEST, response);
    } else if (!request.body.path.startsWith('/')) {
      (0, _logger.log)('wazuh-api:makeRequest', 'Request path is not valid.'); //Path doesn't start with '/'

      return (0, _errorResponse.ErrorResponse)('Request path is not valid.', 3015, _constants.HTTP_STATUS_CODES.BAD_REQUEST, response);
    } else {
      return this.makeRequest(context, request.body.method, request.body.path, request.body.body, request.body.id, response);
    }
  }
  /**
   * Get full data on CSV format from a list Wazuh API endpoint
   * @param {Object} ctx
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} csv or ErrorResponse
   */


  async csv(context, request, response) {
    try {
      if (!request.body || !request.body.path) throw new Error('Field path is required');
      if (!request.body.id) throw new Error('Field id is required');
      const filters = Array.isArray(((request || {}).body || {}).filters) ? request.body.filters : [];
      let tmpPath = request.body.path;

      if (tmpPath && typeof tmpPath === 'string') {
        tmpPath = tmpPath[0] === '/' ? tmpPath.substr(1) : tmpPath;
      }

      if (!tmpPath) throw new Error('An error occurred parsing path field');
      (0, _logger.log)('wazuh-api:csv', `Report ${tmpPath}`, 'debug'); // Real limit, regardless the user query

      const params = {
        limit: 500
      };

      if (filters.length) {
        for (const filter of filters) {
          if (!filter.name || !filter.value) continue;
          params[filter.name] = filter.value;
        }
      }

      let itemsArray = [];
      const output = await context.wazuh.api.client.asCurrentUser.request('GET', `/${tmpPath}`, {
        params: params
      }, {
        apiHostID: request.body.id
      });
      const isList = request.body.path.includes('/lists') && request.body.filters && request.body.filters.length && request.body.filters.find(filter => filter._isCDBList);
      const totalItems = (((output || {}).data || {}).data || {}).total_affected_items;

      if (totalItems && !isList) {
        params.offset = 0;
        itemsArray.push(...output.data.data.affected_items);

        while (itemsArray.length < totalItems && params.offset < totalItems) {
          params.offset += params.limit;
          const tmpData = await context.wazuh.api.client.asCurrentUser.request('GET', `/${tmpPath}`, {
            params: params
          }, {
            apiHostID: request.body.id
          });
          itemsArray.push(...tmpData.data.data.affected_items);
        }
      }

      if (totalItems) {
        const {
          path,
          filters
        } = request.body;
        const isArrayOfLists = path.includes('/lists') && !isList;
        const isAgents = path.includes('/agents') && !path.includes('groups');
        const isAgentsOfGroup = path.startsWith('/agents/groups/');
        const isFiles = path.endsWith('/files');
        let fields = Object.keys(output.data.data.affected_items[0]);

        if (isAgents || isAgentsOfGroup) {
          if (isFiles) {
            fields = ['filename', 'hash'];
          } else {
            fields = ['id', 'status', 'name', 'ip', 'group', 'manager', 'node_name', 'dateAdd', 'version', 'lastKeepAlive', 'os.arch', 'os.build', 'os.codename', 'os.major', 'os.minor', 'os.name', 'os.platform', 'os.uname', 'os.version'];
          }
        }

        if (isArrayOfLists) {
          const flatLists = [];

          for (const list of itemsArray) {
            const {
              relative_dirname,
              items
            } = list;
            flatLists.push(...items.map(item => ({
              relative_dirname,
              key: item.key,
              value: item.value
            })));
          }

          fields = ['relative_dirname', 'key', 'value'];
          itemsArray = [...flatLists];
        }

        if (isList) {
          fields = ['key', 'value'];
          itemsArray = output.data.data.affected_items[0].items;
        }

        fields = fields.map(item => ({
          value: item,
          default: '-'
        }));
        const json2csvParser = new _json2csv.Parser({
          fields
        });
        let csv = json2csvParser.parse(itemsArray);

        for (const field of fields) {
          const {
            value
          } = field;

          if (csv.includes(value)) {
            csv = csv.replace(value, _csvKeyEquivalence.KeyEquivalence[value] || value);
          }
        }

        return response.ok({
          headers: {
            'Content-Type': 'text/csv'
          },
          body: csv
        });
      } else if (output && output.data && output.data.data && !output.data.data.total_affected_items) {
        throw new Error('No results');
      } else {
        throw new Error(`An error occurred fetching data from the Wazuh API${output && output.data && output.data.detail ? `: ${output.body.detail}` : ''}`);
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:csv', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3034, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  } // Get de list of available requests in the API


  getRequestList(context, request, response) {
    //Read a static JSON until the api call has implemented
    return response.ok({
      body: _endpoints.default
    });
  }
  /**
   * This get the timestamp field
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} timestamp field or ErrorResponse
   */


  getTimeStamp(context, request, response) {
    try {
      const source = JSON.parse(_fs.default.readFileSync(this.updateRegistry.file, 'utf8'));

      if (source.installationDate && source.lastRestart) {
        (0, _logger.log)('wazuh-api:getTimeStamp', `Installation date: ${source.installationDate}. Last restart: ${source.lastRestart}`, 'debug');
        return response.ok({
          body: {
            installationDate: source.installationDate,
            lastRestart: source.lastRestart
          }
        });
      } else {
        throw new Error('Could not fetch wazuh-version registry');
      }
    } catch (error) {
      (0, _logger.log)('wazuh-api:getTimeStamp', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || 'Could not fetch wazuh-version registry', 4001, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * This get the extensions
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} extensions object or ErrorResponse
   */


  async setExtensions(context, request, response) {
    try {
      const {
        id,
        extensions
      } = request.body; // Update cluster information in the wazuh-registry.json

      await this.updateRegistry.updateAPIExtensions(id, extensions);
      return response.ok({
        body: {
          statusCode: _constants.HTTP_STATUS_CODES.OK
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:setExtensions', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || 'Could not set extensions', 4001, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * This get the extensions
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} extensions object or ErrorResponse
   */


  getExtensions(context, request, response) {
    try {
      const source = JSON.parse(_fs.default.readFileSync(this.updateRegistry.file, 'utf8'));
      return response.ok({
        body: {
          extensions: (source.hosts[request.params.id] || {}).extensions || {}
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getExtensions', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || 'Could not fetch wazuh-version registry', 4001, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * This get the wazuh setup settings
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} setup info or ErrorResponse
   */


  async getSetupInfo(context, request, response) {
    try {
      const source = JSON.parse(_fs.default.readFileSync(this.updateRegistry.file, 'utf8'));
      return response.ok({
        body: {
          statusCode: _constants.HTTP_STATUS_CODES.OK,
          data: !Object.values(source).length ? '' : source
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getSetupInfo', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not get data from wazuh-version registry due to ${error.message || error}`, 4005, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * Get basic syscollector information for given agent.
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} Basic syscollector information
   */


  async getSyscollector(context, request, response) {
    try {
      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!request.params || !apiHostID || !request.params.agent) {
        throw new Error('Agent ID and API ID are required');
      }

      const {
        agent
      } = request.params;
      const data = await Promise.all([context.wazuh.api.client.asInternalUser.request('GET', `/syscollector/${agent}/hardware`, {}, {
        apiHostID
      }), context.wazuh.api.client.asInternalUser.request('GET', `/syscollector/${agent}/os`, {}, {
        apiHostID
      })]);
      const result = data.map(item => (item.data || {}).data || []);
      const [hardwareResponse, osResponse] = result; // Fill syscollector object

      const syscollector = {
        hardware: typeof hardwareResponse === 'object' && Object.keys(hardwareResponse).length ? { ...hardwareResponse.affected_items[0]
        } : false,
        os: typeof osResponse === 'object' && Object.keys(osResponse).length ? { ...osResponse.affected_items[0]
        } : false
      };
      return response.ok({
        body: syscollector
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getSyscollector', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3035, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * Check if user assigned roles disable Wazuh Plugin
   * @param context
   * @param request
   * @param response
   * @returns {object} Returns { isWazuhDisabled: boolean parsed integer }
   */


  async isWazuhDisabled(context, request, response) {
    try {
      const disabledRoles = (await (0, _getConfiguration.getConfiguration)())['disabled_roles'] || [];
      const logoSidebar = (await (0, _getConfiguration.getConfiguration)())['customization.logo.sidebar'];
      const data = (await context.wazuh.security.getCurrentUser(request, context)).authContext;
      const isWazuhDisabled = +(data.roles || []).some(role => disabledRoles.includes(role));
      return response.ok({
        body: {
          isWazuhDisabled,
          logoSidebar
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:isWazuhDisabled', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3035, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }
  /**
   * Gets custom logos configuration (path)
   * @param context
   * @param request
   * @param response
   */


  async getAppLogos(context, request, response) {
    try {
      const configuration = (0, _getConfiguration.getConfiguration)();
      const SIDEBAR_LOGO = 'customization.logo.sidebar';
      const APP_LOGO = 'customization.logo.app';
      const HEALTHCHECK_LOGO = 'customization.logo.healthcheck';
      const logos = {
        [SIDEBAR_LOGO]: (0, _settings.getCustomizationSetting)(configuration, SIDEBAR_LOGO),
        [APP_LOGO]: (0, _settings.getCustomizationSetting)(configuration, APP_LOGO),
        [HEALTHCHECK_LOGO]: (0, _settings.getCustomizationSetting)(configuration, HEALTHCHECK_LOGO)
      };
      return response.ok({
        body: {
          logos
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-api:getAppLogos', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3035, _constants.HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR, response);
    }
  }

}

exports.WazuhApiCtrl = WazuhApiCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWFwaS50cyJdLCJuYW1lcyI6WyJXYXp1aEFwaUN0cmwiLCJjb25zdHJ1Y3RvciIsIm1hbmFnZUhvc3RzIiwiTWFuYWdlSG9zdHMiLCJ1cGRhdGVSZWdpc3RyeSIsIlVwZGF0ZVJlZ2lzdHJ5IiwiZ2V0VG9rZW4iLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiZm9yY2UiLCJpZEhvc3QiLCJib2R5IiwidXNlcm5hbWUiLCJ3YXp1aCIsInNlY3VyaXR5IiwiZ2V0Q3VycmVudFVzZXIiLCJoZWFkZXJzIiwiY29va2llIiwid3pUb2tlbiIsImRlY29kZWRUb2tlbiIsImV4cGlyYXRpb25UaW1lIiwiZXhwIiwiRGF0ZSIsIm5vdyIsIm9rIiwidG9rZW4iLCJlcnJvciIsIm1lc3NhZ2UiLCJBUElVc2VyQWxsb3dSdW5BcyIsImNhblVzZSIsIkFQSV9VU0VSX1NUQVRVU19SVU5fQVMiLCJFTkFCTEVEIiwiYXBpIiwiY2xpZW50IiwiYXNDdXJyZW50VXNlciIsImF1dGhlbnRpY2F0ZSIsImFzSW50ZXJuYWxVc2VyIiwidGV4dFNlY3VyZSIsInNlcnZlciIsImluZm8iLCJwcm90b2NvbCIsImVycm9yTWVzc2FnZSIsImRhdGEiLCJkZXRhaWwiLCJzdGF0dXMiLCJIVFRQX1NUQVRVU19DT0RFUyIsIklOVEVSTkFMX1NFUlZFUl9FUlJPUiIsImNoZWNrU3RvcmVkQVBJIiwiaWQiLCJnZXRIb3N0QnlJZCIsIk9iamVjdCIsImtleXMiLCJsZW5ndGgiLCJFcnJvciIsInJlc3BvbnNlTWFuYWdlckluZm8iLCJhcGlIb3N0SUQiLCJmb3JjZVJlZnJlc2giLCJjaGVja1Jlc3BvbnNlSXNEb3duIiwiU0VSVklDRV9VTkFWQUlMQUJMRSIsIk9LIiwiY2x1c3Rlcl9pbmZvIiwicmVzcG9uc2VBZ2VudHMiLCJwYXJhbXMiLCJhZ2VudHNfbGlzdCIsIm1hbmFnZXJOYW1lIiwiYWZmZWN0ZWRfaXRlbXMiLCJtYW5hZ2VyIiwicmVzcG9uc2VDbHVzdGVyU3RhdHVzIiwiZW5hYmxlZCIsInJlc3BvbnNlQ2x1c3RlckxvY2FsSW5mbyIsImNsdXN0ZXJFbmFibGVkIiwibm9kZSIsImNsdXN0ZXIiLCJ1cGRhdGVDbHVzdGVySW5mbyIsImNvcGllZCIsInNlY3JldCIsInBhc3N3b3JkIiwic3RhdHVzQ29kZSIsImlkQ2hhbmdlZCIsInVybCIsInBvcnQiLCJjb2RlIiwiYXBpSXNEb3duIiwiYXBpcyIsImdldEhvc3RzIiwidmFsaWRhdGVDaGVja0FwaVBhcmFtcyIsImluY2x1ZGVzIiwiY2hlY2tBUEkiLCJhcGlBdmFpbGFibGUiLCJvcHRpb25zIiwicmVzcG9uc2VDbHVzdGVyIiwiYXBpVXNlckFsbG93UnVuQXMiLCJBTExfRElTQUJMRUQiLCJyZXNwb25zZUFwaVVzZXJBbGxvd1J1bkFzIiwiYWxsb3dfcnVuX2FzIiwicnVuX2FzIiwiVVNFUl9OT1RfQUxMT1dFRCIsIkhPU1RfRElTQUJMRUQiLCJDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMiLCJzZXQiLCJyZXNwb25zZUNsdXN0ZXJMb2NhbCIsIlVOQVVUSE9SSVpFRCIsIkJBRF9SRVFVRVNUIiwic29ja2V0RXJyb3JDb2RlcyIsImlzRG93biIsImNoZWNrRGFlbW9ucyIsInBhdGgiLCJkYWVtb25zIiwiaXNDbHVzdGVyIiwid2F6dWhkYkV4aXN0cyIsImV4ZWNkIiwibW9kdWxlc2QiLCJ3YXp1aGRiIiwiY2x1c3RlcmQiLCJpc1ZhbGlkIiwiUHJvbWlzZSIsInJlamVjdCIsInNsZWVwIiwidGltZU1zIiwicmVzb2x2ZSIsInNldFRpbWVvdXQiLCJzaG91bGRLZWVwQXJyYXlBc0l0IiwibWV0aG9kIiwiaXNBZ2VudHNSZXN0YXJ0IiwiaXNBY3RpdmVSZXNwb25zZSIsInN0YXJ0c1dpdGgiLCJpc0FkZGluZ0FnZW50c1RvR3JvdXAiLCJtYWtlUmVxdWVzdCIsImRldlRvb2xzIiwiTk9UX0ZPVU5EIiwib3JpZ2luIiwiZGVsYXkiLCJzdGFydEF0IiwicnVuIiwiY2hlY2siLCJkYXRhUHJvcGVydGllcyIsImtleSIsIkFycmF5IiwiaXNBcnJheSIsImpvaW4iLCJyZXNwb25zZVRva2VuIiwicmVzcG9uc2VJc0Rvd24iLCJyZXNwb25zZUJvZHkiLCJyZXNwb25zZUVycm9yIiwiZXJyb3JNc2ciLCJBcGlFcnJvckVxdWl2YWxlbmNlIiwicmVxdWVzdEFwaSIsImlkQXBpIiwibWF0Y2giLCJjc3YiLCJmaWx0ZXJzIiwidG1wUGF0aCIsInN1YnN0ciIsImxpbWl0IiwiZmlsdGVyIiwibmFtZSIsInZhbHVlIiwiaXRlbXNBcnJheSIsIm91dHB1dCIsImlzTGlzdCIsImZpbmQiLCJfaXNDREJMaXN0IiwidG90YWxJdGVtcyIsInRvdGFsX2FmZmVjdGVkX2l0ZW1zIiwib2Zmc2V0IiwicHVzaCIsInRtcERhdGEiLCJpc0FycmF5T2ZMaXN0cyIsImlzQWdlbnRzIiwiaXNBZ2VudHNPZkdyb3VwIiwiaXNGaWxlcyIsImVuZHNXaXRoIiwiZmllbGRzIiwiZmxhdExpc3RzIiwibGlzdCIsInJlbGF0aXZlX2Rpcm5hbWUiLCJpdGVtcyIsIm1hcCIsIml0ZW0iLCJkZWZhdWx0IiwianNvbjJjc3ZQYXJzZXIiLCJQYXJzZXIiLCJwYXJzZSIsImZpZWxkIiwicmVwbGFjZSIsIktleUVxdWl2YWxlbmNlIiwiZ2V0UmVxdWVzdExpc3QiLCJhcGlSZXF1ZXN0TGlzdCIsImdldFRpbWVTdGFtcCIsInNvdXJjZSIsIkpTT04iLCJmcyIsInJlYWRGaWxlU3luYyIsImZpbGUiLCJpbnN0YWxsYXRpb25EYXRlIiwibGFzdFJlc3RhcnQiLCJzZXRFeHRlbnNpb25zIiwiZXh0ZW5zaW9ucyIsInVwZGF0ZUFQSUV4dGVuc2lvbnMiLCJnZXRFeHRlbnNpb25zIiwiaG9zdHMiLCJnZXRTZXR1cEluZm8iLCJ2YWx1ZXMiLCJnZXRTeXNjb2xsZWN0b3IiLCJhZ2VudCIsImFsbCIsInJlc3VsdCIsImhhcmR3YXJlUmVzcG9uc2UiLCJvc1Jlc3BvbnNlIiwic3lzY29sbGVjdG9yIiwiaGFyZHdhcmUiLCJvcyIsImlzV2F6dWhEaXNhYmxlZCIsImRpc2FibGVkUm9sZXMiLCJsb2dvU2lkZWJhciIsImF1dGhDb250ZXh0Iiwicm9sZXMiLCJzb21lIiwicm9sZSIsImdldEFwcExvZ29zIiwiY29uZmlndXJhdGlvbiIsIlNJREVCQVJfTE9HTyIsIkFQUF9MT0dPIiwiSEVBTFRIQ0hFQ0tfTE9HTyIsImxvZ29zIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBYUE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBRUE7O0FBQ0E7O0FBRUE7Ozs7OztBQUVPLE1BQU1BLFlBQU4sQ0FBbUI7QUFJeEJDLEVBQUFBLFdBQVcsR0FBRztBQUFBOztBQUFBOztBQUNaLFNBQUtDLFdBQUwsR0FBbUIsSUFBSUMsd0JBQUosRUFBbkI7QUFDQSxTQUFLQyxjQUFMLEdBQXNCLElBQUlDLDhCQUFKLEVBQXRCO0FBQ0Q7O0FBRWEsUUFBUkMsUUFBUSxDQUFDQyxPQUFELEVBQWlDQyxPQUFqQyxFQUF1RUMsUUFBdkUsRUFBc0g7QUFDbEksUUFBSTtBQUNGLFlBQU07QUFBRUMsUUFBQUEsS0FBRjtBQUFTQyxRQUFBQTtBQUFULFVBQW9CSCxPQUFPLENBQUNJLElBQWxDO0FBQ0EsWUFBTTtBQUFFQyxRQUFBQTtBQUFGLFVBQWUsTUFBTU4sT0FBTyxDQUFDTyxLQUFSLENBQWNDLFFBQWQsQ0FBdUJDLGNBQXZCLENBQXNDUixPQUF0QyxFQUErQ0QsT0FBL0MsQ0FBM0I7O0FBQ0EsVUFBSSxDQUFDRyxLQUFELElBQVVGLE9BQU8sQ0FBQ1MsT0FBUixDQUFnQkMsTUFBMUIsSUFBb0NMLFFBQVEsS0FBSyxrQ0FBcUJMLE9BQU8sQ0FBQ1MsT0FBUixDQUFnQkMsTUFBckMsRUFBNkMsU0FBN0MsQ0FBakQsSUFBNEdQLE1BQU0sS0FBSyxrQ0FBcUJILE9BQU8sQ0FBQ1MsT0FBUixDQUFnQkMsTUFBckMsRUFBNEMsUUFBNUMsQ0FBM0gsRUFBa0w7QUFDaEwsY0FBTUMsT0FBTyxHQUFHLGtDQUFxQlgsT0FBTyxDQUFD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QixFQUFzQyxJQUF0QyxFQUE0Q21CLDZCQUFrQkMscUJBQTlELEVBQXFGdEMsUUFBckYsQ0FBUDtBQUNEO0FBRUY7O0FBcmtDdUIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gQ2xhc3MgZm9yIFdhenVoLUFQSSBmdW5jdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbi8vIFJlcXVpcmUgc29tZSBsaWJyYXJpZXNcbmltcG9ydCB7IEVycm9yUmVzcG9uc2UgfSBmcm9tICcuLi9saWIvZXJyb3ItcmVzcG9uc2UnO1xuaW1wb3J0IHsgUGFyc2VyIH0gZnJvbSAnanNvbjJjc3YnO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQgeyBLZXlFcXVpdmFsZW5jZSB9IGZyb20gJy4uLy4uL2NvbW1vbi9jc3Yta2V5LWVxdWl2YWxlbmNlJztcbmltcG9ydCB7IEFwaUVycm9yRXF1aXZhbGVuY2UgfSBmcm9tICcuLi9saWIvYXBpLWVycm9ycy1lcXVpdmFsZW5jZSc7XG5pbXBvcnQgYXBpUmVxdWVzdExpc3QgZnJvbSAnLi4vLi4vY29tbW9uL2FwaS1pbmZvL2VuZHBvaW50cyc7XG5pbXBvcnQgeyBIVFRQX1NUQVRVU19DT0RFUyB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgZ2V0Q3VzdG9taXphdGlvblNldHRpbmcgfSBmcm9tICcuLi8uLi9jb21tb24vc2VydmljZXMvc2V0dGluZ3MnO1xuaW1wb3J0IHsgYWRkSm9iVG9RdWV1ZSB9IGZyb20gJy4uL3N0YXJ0L3F1ZXVlJztcbmltcG9ydCBmcyBmcm9tICdmcyc7XG5pbXBvcnQgeyBNYW5hZ2VIb3N0cyB9IGZyb20gJy4uL2xpYi9tYW5hZ2UtaG9zdHMnO1xuaW1wb3J0IHsgVXBkYXRlUmVnaXN0cnkgfSBmcm9tICcuLi9saWIvdXBkYXRlLXJlZ2lzdHJ5JztcbmltcG9ydCBqd3REZWNvZGUgZnJvbSAnand0LWRlY29kZSc7XG5pbXBvcnQgeyBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkgfSBmcm9tICdzcmMvY29yZS9zZXJ2ZXInO1xuaW1wb3J0IHsgQVBJVXNlckFsbG93UnVuQXMsIENhY2hlSW5NZW1vcnlBUElVc2VyQWxsb3dSdW5BcywgQVBJX1VTRVJfU1RBVFVTX1JVTl9BUyB9IGZyb20gJy4uL2xpYi9jYWNoZS1hcGktdXNlci1oYXMtcnVuLWFzJztcbmltcG9ydCB7IGdldENvb2tpZVZhbHVlQnlOYW1lIH0gZnJvbSAnLi4vbGliL2Nvb2tpZSc7XG5pbXBvcnQgeyBTZWN1cml0eU9iaiB9IGZyb20gJy4uL2xpYi9zZWN1cml0eS1mYWN0b3J5JztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuXG5leHBvcnQgY2xhc3MgV2F6dWhBcGlDdHJsIHtcbiAgbWFuYWdlSG9zdHM6IE1hbmFnZUhvc3RzXG4gIHVwZGF0ZVJlZ2lzdHJ5OiBVcGRhdGVSZWdpc3RyeVxuXG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMubWFuYWdlSG9zdHMgPSBuZXcgTWFuYWdlSG9zdHMoKTtcbiAgICB0aGlzLnVwZGF0ZVJlZ2lzdHJ5ID0gbmV3IFVwZGF0ZVJlZ2lzdHJ5KCk7XG4gIH1cblxuICBhc3luYyBnZXRUb2tlbihjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgZm9yY2UsIGlkSG9zdCB9ID0gcmVxdWVzdC5ib2R5O1xuICAgICAgY29uc3QgeyB1c2VybmFtZSB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5zZWN1cml0eS5nZXRDdXJyZW50VXNlcihyZXF1ZXN0LCBjb250ZXh0KTtcbiAgICAgIGlmICghZm9yY2UgJiYgcmVxdWVzdC5oZWFkZXJzLmNvb2tpZSAmJiB1c2VybmFtZSA9PT0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LXVzZXInKSAmJiBpZEhvc3QgPT09IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsJ3d6LWFwaScpKSB7XG4gICAgICAgIGNvbnN0IHd6VG9rZW4gPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCAnd3otdG9rZW4nKTtcbiAgICAgICAgaWYgKHd6VG9rZW4pIHtcbiAgICAgICAgICB0cnkgeyAvLyBpZiB0aGUgY3VycmVudCB0b2tlbiBpcyBub3QgYSB2YWxpZCBqd3QgdG9rZW4gd2UgYXNrIGZvciBhIG5ldyBvbmVcbiAgICAgICAgICAgIGNvbnN0IGRlY29kZWRUb2tlbiA9IGp3dERlY29kZSh3elRva2VuKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyYXRpb25UaW1lID0gKGRlY29kZWRUb2tlbi5leHAgLSAoRGF0ZS5ub3coKSAvIDEwMDApKTtcbiAgICAgICAgICAgIGlmICh3elRva2VuICYmIGV4cGlyYXRpb25UaW1lID4gMCkge1xuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgICAgICAgIGJvZHk6IHsgdG9rZW46IHd6VG9rZW4gfVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgbG9nKCd3YXp1aC1hcGk6Z2V0VG9rZW4nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGxldCB0b2tlbjtcbiAgICAgIGlmIChhd2FpdCBBUElVc2VyQWxsb3dSdW5Bcy5jYW5Vc2UoaWRIb3N0KSA9PSBBUElfVVNFUl9TVEFUVVNfUlVOX0FTLkVOQUJMRUQpIHtcbiAgICAgICAgdG9rZW4gPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5hdXRoZW50aWNhdGUoaWRIb3N0KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRva2VuID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLmF1dGhlbnRpY2F0ZShpZEhvc3QpO1xuICAgICAgfTtcblxuICAgICAgbGV0IHRleHRTZWN1cmU9Jyc7XG4gICAgICBpZihjb250ZXh0LndhenVoLnNlcnZlci5pbmZvLnByb3RvY29sID09PSAnaHR0cHMnKXtcbiAgICAgICAgdGV4dFNlY3VyZSA9ICc7U2VjdXJlJztcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICdzZXQtY29va2llJzogW1xuICAgICAgICAgICAgYHd6LXRva2VuPSR7dG9rZW59O1BhdGg9LztIdHRwT25seSR7dGV4dFNlY3VyZX1gLFxuICAgICAgICAgICAgYHd6LXVzZXI9JHt1c2VybmFtZX07UGF0aD0vO0h0dHBPbmx5JHt0ZXh0U2VjdXJlfWAsXG4gICAgICAgICAgICBgd3otYXBpPSR7aWRIb3N0fTtQYXRoPS87SHR0cE9ubHlgLFxuICAgICAgICAgIF0sXG4gICAgICAgIH0sXG4gICAgICAgIGJvZHk6IHsgdG9rZW4gfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9ICgoZXJyb3IucmVzcG9uc2UgfHwge30pLmRhdGEgfHwge30pLmRldGFpbCB8fCBlcnJvci5tZXNzYWdlIHx8IGVycm9yO1xuICAgICAgbG9nKCd3YXp1aC1hcGk6Z2V0VG9rZW4nLCBlcnJvck1lc3NhZ2UpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGBFcnJvciBnZXR0aW5nIHRoZSBhdXRob3JpemF0aW9uIHRva2VuOiAke2Vycm9yTWVzc2FnZX1gLFxuICAgICAgICAzMDAwLFxuICAgICAgICBlcnJvcj8ucmVzcG9uc2U/LnN0YXR1cyB8fCBIVFRQX1NUQVRVU19DT0RFUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIGlmIHRoZSB3YXp1aC1hcGkgY29uZmlndXJhdGlvbiBpcyB3b3JraW5nXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBzdGF0dXMgb2JqIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNoZWNrU3RvcmVkQVBJKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgLy8gR2V0IGNvbmZpZyBmcm9tIHdhenVoLnltbFxuICAgICAgY29uc3QgaWQgPSByZXF1ZXN0LmJvZHkuaWQ7XG4gICAgICBjb25zdCBhcGkgPSBhd2FpdCB0aGlzLm1hbmFnZUhvc3RzLmdldEhvc3RCeUlkKGlkKTtcbiAgICAgIC8vIENoZWNrIE1hbmFnZSBIb3N0c1xuICAgICAgaWYgKCFPYmplY3Qua2V5cyhhcGkpLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NvdWxkIG5vdCBmaW5kIFdhenVoIEFQSSBlbnRyeSBvbiB3YXp1aC55bWwnKTtcbiAgICAgIH1cblxuICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tTdG9yZWRBUEknLCBgJHtpZH0gZXhpc3RzYCwgJ2RlYnVnJyk7XG5cbiAgICAgIC8vIEZldGNoIG5lZWRlZCBpbmZvcm1hdGlvbiBhYm91dCB0aGUgY2x1c3RlciBhbmQgdGhlIG1hbmFnZXIgaXRzZWxmXG4gICAgICBjb25zdCByZXNwb25zZU1hbmFnZXJJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICdnZXQnLFxuICAgICAgICBgL21hbmFnZXIvaW5mb2AsXG4gICAgICAgIHt9LFxuICAgICAgICB7IGFwaUhvc3RJRDogaWQsIGZvcmNlUmVmcmVzaDogdHJ1ZSB9XG4gICAgICApO1xuXG4gICAgICAvLyBMb29rIGZvciBzb2NrZXQtcmVsYXRlZCBlcnJvcnNcbiAgICAgIGlmICh0aGlzLmNoZWNrUmVzcG9uc2VJc0Rvd24ocmVzcG9uc2VNYW5hZ2VySW5mbykpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgYEVSUk9SMzA5OSAtICR7cmVzcG9uc2VNYW5hZ2VySW5mby5kYXRhLmRldGFpbCB8fCAnV2F6dWggbm90IHJlYWR5IHlldCd9YCxcbiAgICAgICAgICAzMDk5LFxuICAgICAgICAgIEhUVFBfU1RBVFVTX0NPREVTLlNFUlZJQ0VfVU5BVkFJTEFCTEUsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgLy8gSWYgd2UgaGF2ZSBhIHZhbGlkIHJlc3BvbnNlIGZyb20gdGhlIFdhenVoIEFQSVxuICAgICAgaWYgKHJlc3BvbnNlTWFuYWdlckluZm8uc3RhdHVzID09PSBIVFRQX1NUQVRVU19DT0RFUy5PSyAmJiByZXNwb25zZU1hbmFnZXJJbmZvLmRhdGEpIHtcbiAgICAgICAgLy8gQ2xlYXIgYW5kIHVwZGF0ZSBjbHVzdGVyIGluZm9ybWF0aW9uIGJlZm9yZSBiZWluZyBzZW50IGJhY2sgdG8gZnJvbnRlbmRcbiAgICAgICAgZGVsZXRlIGFwaS5jbHVzdGVyX2luZm87XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlQWdlbnRzID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9hZ2VudHNgLFxuICAgICAgICAgIHsgcGFyYW1zOiB7IGFnZW50c19saXN0OiAnMDAwJyB9IH0sXG4gICAgICAgICAgeyBhcGlIb3N0SUQ6IGlkIH1cbiAgICAgICAgKTtcblxuICAgICAgICBpZiAocmVzcG9uc2VBZ2VudHMuc3RhdHVzID09PSBIVFRQX1NUQVRVU19DT0RFUy5PSykge1xuICAgICAgICAgIGNvbnN0IG1hbmFnZXJOYW1lID0gcmVzcG9uc2VBZ2VudHMuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLm1hbmFnZXI7XG5cbiAgICAgICAgICBjb25zdCByZXNwb25zZUNsdXN0ZXJTdGF0dXMgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYC9jbHVzdGVyL3N0YXR1c2AsXG4gICAgICAgICAgICB7fSxcbiAgICAgICAgICAgIHsgYXBpSG9zdElEOiBpZCB9XG4gICAgICAgICAgKTtcbiAgICAgICAgICBpZiAocmVzcG9uc2VDbHVzdGVyU3RhdHVzLnN0YXR1cyA9PT0gSFRUUF9TVEFUVVNfQ09ERVMuT0spIHtcbiAgICAgICAgICAgIGlmIChyZXNwb25zZUNsdXN0ZXJTdGF0dXMuZGF0YS5kYXRhLmVuYWJsZWQgPT09ICd5ZXMnKSB7XG4gICAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlQ2x1c3RlckxvY2FsSW5mbyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgICAgIGAvY2x1c3Rlci9sb2NhbC9pbmZvYCxcbiAgICAgICAgICAgICAgICB7fSxcbiAgICAgICAgICAgICAgICB7IGFwaUhvc3RJRDogaWQgfVxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDbHVzdGVyTG9jYWxJbmZvLnN0YXR1cyA9PT0gSFRUUF9TVEFUVVNfQ09ERVMuT0spIHtcbiAgICAgICAgICAgICAgICBjb25zdCBjbHVzdGVyRW5hYmxlZCA9IHJlc3BvbnNlQ2x1c3RlclN0YXR1cy5kYXRhLmRhdGEuZW5hYmxlZCA9PT0gJ3llcyc7XG4gICAgICAgICAgICAgICAgYXBpLmNsdXN0ZXJfaW5mbyA9IHtcbiAgICAgICAgICAgICAgICAgIHN0YXR1czogY2x1c3RlckVuYWJsZWQgPyAnZW5hYmxlZCcgOiAnZGlzYWJsZWQnLFxuICAgICAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgICAgICBub2RlOiByZXNwb25zZUNsdXN0ZXJMb2NhbEluZm8uZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLm5vZGUsXG4gICAgICAgICAgICAgICAgICBjbHVzdGVyOiBjbHVzdGVyRW5hYmxlZFxuICAgICAgICAgICAgICAgICAgICA/IHJlc3BvbnNlQ2x1c3RlckxvY2FsSW5mby5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uY2x1c3RlclxuICAgICAgICAgICAgICAgICAgICA6ICdEaXNhYmxlZCcsXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgLy8gQ2x1c3RlciBtb2RlIGlzIG5vdCBhY3RpdmVcbiAgICAgICAgICAgICAgYXBpLmNsdXN0ZXJfaW5mbyA9IHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6ICdkaXNhYmxlZCcsXG4gICAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgICAgY2x1c3RlcjogJ0Rpc2FibGVkJyxcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8gQ2x1c3RlciBtb2RlIGlzIG5vdCBhY3RpdmVcbiAgICAgICAgICAgIGFwaS5jbHVzdGVyX2luZm8gPSB7XG4gICAgICAgICAgICAgIHN0YXR1czogJ2Rpc2FibGVkJyxcbiAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgIGNsdXN0ZXI6ICdEaXNhYmxlZCcsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChhcGkuY2x1c3Rlcl9pbmZvKSB7XG4gICAgICAgICAgICAvLyBVcGRhdGUgY2x1c3RlciBpbmZvcm1hdGlvbiBpbiB0aGUgd2F6dWgtcmVnaXN0cnkuanNvblxuICAgICAgICAgICAgYXdhaXQgdGhpcy51cGRhdGVSZWdpc3RyeS51cGRhdGVDbHVzdGVySW5mbyhpZCwgYXBpLmNsdXN0ZXJfaW5mbyk7XG5cbiAgICAgICAgICAgIC8vIEhpZGUgV2F6dWggQVBJIHNlY3JldCwgdXNlcm5hbWUsIHBhc3N3b3JkXG4gICAgICAgICAgICBjb25zdCBjb3BpZWQgPSB7IC4uLmFwaSB9O1xuICAgICAgICAgICAgY29waWVkLnNlY3JldCA9ICcqKioqJztcbiAgICAgICAgICAgIGNvcGllZC5wYXNzd29yZCA9ICcqKioqJztcblxuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgICAgIHN0YXR1c0NvZGU6IEhUVFBfU1RBVFVTX0NPREVTLk9LLFxuICAgICAgICAgICAgICAgIGRhdGE6IGNvcGllZCxcbiAgICAgICAgICAgICAgICBpZENoYW5nZWQ6IHJlcXVlc3QuYm9keS5pZENoYW5nZWQgfHwgbnVsbCxcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vIElmIHdlIGhhdmUgYW4gaW52YWxpZCByZXNwb25zZSBmcm9tIHRoZSBXYXp1aCBBUElcbiAgICAgIHRocm93IG5ldyBFcnJvcihyZXNwb25zZU1hbmFnZXJJbmZvLmRhdGEuZGV0YWlsIHx8IGAke2FwaS51cmx9OiR7YXBpLnBvcnR9IGlzIHVucmVhY2hhYmxlYCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGlmIChlcnJvci5jb2RlID09PSAnRVBST1RPJykge1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IEhUVFBfU1RBVFVTX0NPREVTLk9LLFxuICAgICAgICAgICAgZGF0YTogeyBhcGlJc0Rvd246IHRydWUgfSxcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIGlmIChlcnJvci5jb2RlID09PSAnRUNPTk5SRUZVU0VEJykge1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IEhUVFBfU1RBVFVTX0NPREVTLk9LLFxuICAgICAgICAgICAgZGF0YTogeyBhcGlJc0Rvd246IHRydWUgfSxcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCBhcGlzID0gYXdhaXQgdGhpcy5tYW5hZ2VIb3N0cy5nZXRIb3N0cygpO1xuICAgICAgICAgIGZvciAoY29uc3QgYXBpIG9mIGFwaXMpIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IGlkID0gT2JqZWN0LmtleXMoYXBpKVswXTtcblxuICAgICAgICAgICAgICBjb25zdCByZXNwb25zZU1hbmFnZXJJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICAgICAgYC9tYW5hZ2VyL2luZm9gLFxuICAgICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiBpZCB9XG4gICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgaWYgKHRoaXMuY2hlY2tSZXNwb25zZUlzRG93bihyZXNwb25zZU1hbmFnZXJJbmZvKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgYEVSUk9SMzA5OSAtICR7cmVzcG9uc2UuZGF0YS5kZXRhaWwgfHwgJ1dhenVoIG5vdCByZWFkeSB5ZXQnfWAsXG4gICAgICAgICAgICAgICAgICAzMDk5LFxuICAgICAgICAgICAgICAgICAgSFRUUF9TVEFUVVNfQ09ERVMuU0VSVklDRV9VTkFWQUlMQUJMRSxcbiAgICAgICAgICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBpZiAocmVzcG9uc2VNYW5hZ2VySW5mby5zdGF0dXMgPT09IEhUVFBfU1RBVFVTX0NPREVTLk9LKSB7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5ib2R5LmlkID0gaWQ7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5ib2R5LmlkQ2hhbmdlZCA9IGlkO1xuICAgICAgICAgICAgICAgIHJldHVybiBhd2FpdCB0aGlzLmNoZWNrU3RvcmVkQVBJKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHsgfSAvLyBlc2xpbnQtZGlzYWJsZS1saW5lXG4gICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrU3RvcmVkQVBJJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgICBlcnJvci5tZXNzYWdlIHx8IGVycm9yLFxuICAgICAgICAgICAgMzAyMCxcbiAgICAgICAgICAgIGVycm9yPy5yZXNwb25zZT8uc3RhdHVzIHx8IEhUVFBfU1RBVFVTX0NPREVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgICBsb2coJ3dhenVoLWFwaTpjaGVja1N0b3JlZEFQSScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICBlcnJvci5tZXNzYWdlIHx8IGVycm9yLFxuICAgICAgICAgIDMwMDIsXG4gICAgICAgICAgZXJyb3I/LnJlc3BvbnNlPy5zdGF0dXMgfHwgSFRUUF9TVEFUVVNfQ09ERVMuSU5URVJOQUxfU0VSVkVSX0VSUk9SLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcGVyZm9tcyBhIHZhbGlkYXRpb24gb2YgQVBJIHBhcmFtc1xuICAgKiBAcGFyYW0ge09iamVjdH0gYm9keSBBUEkgcGFyYW1zXG4gICAqL1xuICB2YWxpZGF0ZUNoZWNrQXBpUGFyYW1zKGJvZHkpIHtcbiAgICBpZiAoISgndXNlcm5hbWUnIGluIGJvZHkpKSB7XG4gICAgICByZXR1cm4gJ01pc3NpbmcgcGFyYW06IEFQSSBVU0VSTkFNRSc7XG4gICAgfVxuXG4gICAgaWYgKCEoJ3Bhc3N3b3JkJyBpbiBib2R5KSAmJiAhKCdpZCcgaW4gYm9keSkpIHtcbiAgICAgIHJldHVybiAnTWlzc2luZyBwYXJhbTogQVBJIFBBU1NXT1JEJztcbiAgICB9XG5cbiAgICBpZiAoISgndXJsJyBpbiBib2R5KSkge1xuICAgICAgcmV0dXJuICdNaXNzaW5nIHBhcmFtOiBBUEkgVVJMJztcbiAgICB9XG5cbiAgICBpZiAoISgncG9ydCcgaW4gYm9keSkpIHtcbiAgICAgIHJldHVybiAnTWlzc2luZyBwYXJhbTogQVBJIFBPUlQnO1xuICAgIH1cblxuICAgIGlmICghYm9keS51cmwuaW5jbHVkZXMoJ2h0dHBzOi8vJykgJiYgIWJvZHkudXJsLmluY2x1ZGVzKCdodHRwOi8vJykpIHtcbiAgICAgIHJldHVybiAncHJvdG9jb2xfZXJyb3InO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGNoZWNrIHRoZSB3YXp1aC1hcGkgY29uZmlndXJhdGlvbiByZWNlaXZlZCBpbiB0aGUgUE9TVCBib2R5IHdpbGwgd29ya1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gc3RhdHVzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjaGVja0FQSShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGxldCBhcGlBdmFpbGFibGUgPSBudWxsO1xuICAgICAgLy8gY29uc3Qgbm90VmFsaWQgPSB0aGlzLnZhbGlkYXRlQ2hlY2tBcGlQYXJhbXMocmVxdWVzdC5ib2R5KTtcbiAgICAgIC8vIGlmIChub3RWYWxpZCkgcmV0dXJuIEVycm9yUmVzcG9uc2Uobm90VmFsaWQsIDMwMDMsIEhUVFBfU1RBVFVTX0NPREVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUiwgcmVzcG9uc2UpO1xuICAgICAgbG9nKCd3YXp1aC1hcGk6Y2hlY2tBUEknLCBgJHtyZXF1ZXN0LmJvZHkuaWR9IGlzIHZhbGlkYCwgJ2RlYnVnJyk7XG4gICAgICAvLyBDaGVjayBpZiBhIFdhenVoIEFQSSBpZCBpcyBnaXZlbiAoYWxyZWFkeSBzdG9yZWQgQVBJKVxuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHRoaXMubWFuYWdlSG9zdHMuZ2V0SG9zdEJ5SWQocmVxdWVzdC5ib2R5LmlkKTtcbiAgICAgIGlmIChkYXRhKSB7XG4gICAgICAgIGFwaUF2YWlsYWJsZSA9IGRhdGE7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsb2coJ3dhenVoLWFwaTpjaGVja0FQSScsIGBBUEkgJHtyZXF1ZXN0LmJvZHkuaWR9IG5vdCBmb3VuZGApO1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICBgVGhlIEFQSSAke3JlcXVlc3QuYm9keS5pZH0gd2FzIG5vdCBmb3VuZGAsXG4gICAgICAgICAgMzAyOSxcbiAgICAgICAgICBIVFRQX1NUQVRVU19DT0RFUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IG9wdGlvbnMgPSB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH07XG4gICAgICBpZiAocmVxdWVzdC5ib2R5LmZvcmNlUmVmcmVzaCkge1xuICAgICAgICBvcHRpb25zW1wiZm9yY2VSZWZyZXNoXCJdID0gcmVxdWVzdC5ib2R5LmZvcmNlUmVmcmVzaDtcbiAgICAgIH1cbiAgICAgIGxldCByZXNwb25zZU1hbmFnZXJJbmZvO1xuICAgICAgdHJ5e1xuICAgICAgICByZXNwb25zZU1hbmFnZXJJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9tYW5hZ2VyL2luZm9gLFxuICAgICAgICAgIHt9LFxuICAgICAgICAgIG9wdGlvbnNcbiAgICAgICAgKTtcbiAgICAgIH1jYXRjaChlcnJvcil7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgIGBFUlJPUjMwOTkgLSAke2Vycm9yLnJlc3BvbnNlPy5kYXRhPy5kZXRhaWwgfHwgJ1dhenVoIG5vdCByZWFkeSB5ZXQnfWAsXG4gICAgICAgICAgMzA5OSxcbiAgICAgICAgICBlcnJvcj8ucmVzcG9uc2U/LnN0YXR1cyB8fCBIVFRQX1NUQVRVU19DT0RFUy5TRVJWSUNFX1VOQVZBSUxBQkxFLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrQVBJJywgYCR7cmVxdWVzdC5ib2R5LmlkfSBjcmVkZW50aWFscyBhcmUgdmFsaWRgLCAnZGVidWcnKTtcbiAgICAgIGlmIChyZXNwb25zZU1hbmFnZXJJbmZvLnN0YXR1cyA9PT0gSFRUUF9TVEFUVVNfQ09ERVMuT0sgJiYgcmVzcG9uc2VNYW5hZ2VySW5mby5kYXRhKSB7XG4gICAgICAgIGxldCByZXNwb25zZUFnZW50cyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgIGAvYWdlbnRzYCxcbiAgICAgICAgICB7IHBhcmFtczogeyBhZ2VudHNfbGlzdDogJzAwMCcgfSB9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiByZXF1ZXN0LmJvZHkuaWQgfVxuICAgICAgICApO1xuXG4gICAgICAgIGlmIChyZXNwb25zZUFnZW50cy5zdGF0dXMgPT09IEhUVFBfU1RBVFVTX0NPREVTLk9LKSB7XG4gICAgICAgICAgY29uc3QgbWFuYWdlck5hbWUgPSByZXNwb25zZUFnZW50cy5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0ubWFuYWdlcjtcblxuICAgICAgICAgIGxldCByZXNwb25zZUNsdXN0ZXIgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYC9jbHVzdGVyL3N0YXR1c2AsXG4gICAgICAgICAgICB7fSxcbiAgICAgICAgICAgIHsgYXBpSG9zdElEOiByZXF1ZXN0LmJvZHkuaWQgfVxuICAgICAgICAgICk7XG5cbiAgICAgICAgICAvLyBDaGVjayB0aGUgcnVuX2FzIGZvciB0aGUgQVBJIHVzZXIgYW5kIHVwZGF0ZSBpdFxuICAgICAgICAgIGxldCBhcGlVc2VyQWxsb3dSdW5BcyA9IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuQUxMX0RJU0FCTEVEO1xuICAgICAgICAgIGNvbnN0IHJlc3BvbnNlQXBpVXNlckFsbG93UnVuQXMgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYC9zZWN1cml0eS91c2Vycy9tZWAsXG4gICAgICAgICAgICB7fSxcbiAgICAgICAgICAgIHsgYXBpSG9zdElEOiByZXF1ZXN0LmJvZHkuaWQgfVxuICAgICAgICAgICk7XG4gICAgICAgICAgaWYgKHJlc3BvbnNlQXBpVXNlckFsbG93UnVuQXMuc3RhdHVzID09PSBIVFRQX1NUQVRVU19DT0RFUy5PSykge1xuICAgICAgICAgICAgY29uc3QgYWxsb3dfcnVuX2FzID0gcmVzcG9uc2VBcGlVc2VyQWxsb3dSdW5Bcy5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uYWxsb3dfcnVuX2FzO1xuXG4gICAgICAgICAgICBpZiAoYWxsb3dfcnVuX2FzICYmIGFwaUF2YWlsYWJsZSAmJiBhcGlBdmFpbGFibGUucnVuX2FzKSAvLyBIT1NUIEFORCBVU0VSIEVOQUJMRURcbiAgICAgICAgICAgICAgYXBpVXNlckFsbG93UnVuQXMgPSBBUElfVVNFUl9TVEFUVVNfUlVOX0FTLkVOQUJMRUQ7XG5cbiAgICAgICAgICAgIGVsc2UgaWYgKCFhbGxvd19ydW5fYXMgJiYgYXBpQXZhaWxhYmxlICYmIGFwaUF2YWlsYWJsZS5ydW5fYXMpLy8gSE9TVCBFTkFCTEVEIEFORCBVU0VSIERJU0FCTEVEXG4gICAgICAgICAgICAgIGFwaVVzZXJBbGxvd1J1bkFzID0gQVBJX1VTRVJfU1RBVFVTX1JVTl9BUy5VU0VSX05PVF9BTExPV0VEO1xuXG4gICAgICAgICAgICBlbHNlIGlmIChhbGxvd19ydW5fYXMgJiYgKCAhYXBpQXZhaWxhYmxlIHx8ICFhcGlBdmFpbGFibGUucnVuX2FzICkpIC8vIFVTRVIgRU5BQkxFRCBBTkQgSE9TVCBESVNBQkxFRFxuICAgICAgICAgICAgICBhcGlVc2VyQWxsb3dSdW5BcyA9IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuSE9TVF9ESVNBQkxFRDtcblxuICAgICAgICAgICAgZWxzZSBpZiAoIWFsbG93X3J1bl9hcyAmJiAoICFhcGlBdmFpbGFibGUgfHwgIWFwaUF2YWlsYWJsZS5ydW5fYXMgKSkgLy8gSE9TVCBBTkQgVVNFUiBESVNBQkxFRFxuICAgICAgICAgICAgICBhcGlVc2VyQWxsb3dSdW5BcyA9IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuQUxMX0RJU0FCTEVEO1xuICAgICAgICAgIH1cbiAgICAgICAgICBDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMuc2V0KFxuICAgICAgICAgICAgcmVxdWVzdC5ib2R5LmlkLFxuICAgICAgICAgICAgYXBpQXZhaWxhYmxlLnVzZXJuYW1lLFxuICAgICAgICAgICAgYXBpVXNlckFsbG93UnVuQXNcbiAgICAgICAgICApO1xuXG4gICAgICAgICAgaWYgKHJlc3BvbnNlQ2x1c3Rlci5zdGF0dXMgPT09IEhUVFBfU1RBVFVTX0NPREVTLk9LKSB7XG4gICAgICAgICAgICBsb2coJ3dhenVoLWFwaTpjaGVja1N0b3JlZEFQSScsIGBXYXp1aCBBUEkgcmVzcG9uc2UgaXMgdmFsaWRgLCAnZGVidWcnKTtcbiAgICAgICAgICAgIGlmIChyZXNwb25zZUNsdXN0ZXIuZGF0YS5kYXRhLmVuYWJsZWQgPT09ICd5ZXMnKSB7XG4gICAgICAgICAgICAgIC8vIElmIGNsdXN0ZXIgbW9kZSBpcyBhY3RpdmVcbiAgICAgICAgICAgICAgbGV0IHJlc3BvbnNlQ2x1c3RlckxvY2FsID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICAgICAgYC9jbHVzdGVyL2xvY2FsL2luZm9gLFxuICAgICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiByZXF1ZXN0LmJvZHkuaWQgfVxuICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZUNsdXN0ZXJMb2NhbC5zdGF0dXMgPT09IEhUVFBfU1RBVFVTX0NPREVTLk9LKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgICAgICAgICAgbWFuYWdlcjogbWFuYWdlck5hbWUsXG4gICAgICAgICAgICAgICAgICAgIG5vZGU6IHJlc3BvbnNlQ2x1c3RlckxvY2FsLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXS5ub2RlLFxuICAgICAgICAgICAgICAgICAgICBjbHVzdGVyOiByZXNwb25zZUNsdXN0ZXJMb2NhbC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uY2x1c3RlcixcbiAgICAgICAgICAgICAgICAgICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgICAgICAgICAgICAgICAgIGFsbG93X3J1bl9hczogYXBpVXNlckFsbG93UnVuQXMsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAvLyBDbHVzdGVyIG1vZGUgaXMgbm90IGFjdGl2ZVxuICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgICAgICAgIG1hbmFnZXI6IG1hbmFnZXJOYW1lLFxuICAgICAgICAgICAgICAgICAgY2x1c3RlcjogJ0Rpc2FibGVkJyxcbiAgICAgICAgICAgICAgICAgIHN0YXR1czogJ2Rpc2FibGVkJyxcbiAgICAgICAgICAgICAgICAgIGFsbG93X3J1bl9hczogYXBpVXNlckFsbG93UnVuQXMsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrQVBJJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG5cbiAgICAgIGlmIChlcnJvciAmJiBlcnJvci5yZXNwb25zZSAmJiBlcnJvci5yZXNwb25zZS5zdGF0dXMgPT09IEhUVFBfU1RBVFVTX0NPREVTLlVOQVVUSE9SSVpFRCkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICBgVW5hdGhvcml6ZWQuIFBsZWFzZSBjaGVjayBBUEkgY3JlZGVudGlhbHMuICR7ZXJyb3IucmVzcG9uc2UuZGF0YS5tZXNzYWdlfWAsXG4gICAgICAgICAgSFRUUF9TVEFUVVNfQ09ERVMuVU5BVVRIT1JJWkVELFxuICAgICAgICAgIEhUVFBfU1RBVFVTX0NPREVTLlVOQVVUSE9SSVpFRCxcbiAgICAgICAgICByZXNwb25zZVxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgaWYgKGVycm9yICYmIGVycm9yLnJlc3BvbnNlICYmIGVycm9yLnJlc3BvbnNlLmRhdGEgJiYgZXJyb3IucmVzcG9uc2UuZGF0YS5kZXRhaWwpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgZXJyb3IucmVzcG9uc2UuZGF0YS5kZXRhaWwsXG4gICAgICAgICAgZXJyb3IucmVzcG9uc2Uuc3RhdHVzIHx8IEhUVFBfU1RBVFVTX0NPREVTLlNFUlZJQ0VfVU5BVkFJTEFCTEUsXG4gICAgICAgICAgZXJyb3IucmVzcG9uc2Uuc3RhdHVzIHx8IEhUVFBfU1RBVFVTX0NPREVTLlNFUlZJQ0VfVU5BVkFJTEFCTEUsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGlmIChlcnJvci5jb2RlID09PSAnRVBST1RPJykge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgICAnV3JvbmcgcHJvdG9jb2wgYmVpbmcgdXNlZCB0byBjb25uZWN0IHRvIHRoZSBXYXp1aCBBUEknLFxuICAgICAgICAgIDMwMDUsXG4gICAgICAgICAgSFRUUF9TVEFUVVNfQ09ERVMuQkFEX1JFUVVFU1QsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICBlcnJvci5tZXNzYWdlIHx8IGVycm9yLFxuICAgICAgICAzMDA1LFxuICAgICAgICBlcnJvcj8ucmVzcG9uc2U/LnN0YXR1cyB8fCBIVFRQX1NUQVRVU19DT0RFUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIGNoZWNrUmVzcG9uc2VJc0Rvd24ocmVzcG9uc2UpIHtcbiAgICBpZiAocmVzcG9uc2Uuc3RhdHVzICE9PSBIVFRQX1NUQVRVU19DT0RFUy5PSykge1xuICAgICAgLy8gQXZvaWQgXCJFcnJvciBjb21tdW5pY2F0aW5nIHdpdGggc29ja2V0XCIgbGlrZSBlcnJvcnNcbiAgICAgIGNvbnN0IHNvY2tldEVycm9yQ29kZXMgPSBbMTAxMywgMTAxNCwgMTAxNywgMTAxOCwgMTAxOV07XG4gICAgICBjb25zdCBzdGF0dXMgPSAocmVzcG9uc2UuZGF0YSB8fCB7fSkuc3RhdHVzIHx8IDFcbiAgICAgIGNvbnN0IGlzRG93biA9IHNvY2tldEVycm9yQ29kZXMuaW5jbHVkZXMoc3RhdHVzKTtcblxuICAgICAgaXNEb3duICYmIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgJ1dhenVoIEFQSSBpcyBvbmxpbmUgYnV0IFdhenVoIGlzIG5vdCByZWFkeSB5ZXQnKTtcblxuICAgICAgcmV0dXJuIGlzRG93bjtcbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrIG1haW4gV2F6dWggZGFlbW9ucyBzdGF0dXNcbiAgICogQHBhcmFtIHsqfSBjb250ZXh0IEVuZHBvaW50IGNvbnRleHRcbiAgICogQHBhcmFtIHsqfSBhcGkgQVBJIGVudHJ5IHN0b3JlZCBpbiAud2F6dWhcbiAgICogQHBhcmFtIHsqfSBwYXRoIE9wdGlvbmFsLiBXYXp1aCBBUEkgdGFyZ2V0IHBhdGguXG4gICAqL1xuICBhc3luYyBjaGVja0RhZW1vbnMoY29udGV4dCwgYXBpLCBwYXRoKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAgICdHRVQnLFxuICAgICAgICAnL21hbmFnZXIvc3RhdHVzJyxcbiAgICAgICAge30sXG4gICAgICAgIHsgYXBpSG9zdElEOiBhcGkuaWQgfVxuICAgICAgKTtcblxuICAgICAgY29uc3QgZGFlbW9ucyA9ICgoKChyZXNwb25zZSB8fCB7fSkuZGF0YSB8fCB7fSkuZGF0YSB8fCB7fSkuYWZmZWN0ZWRfaXRlbXMgfHwgW10pWzBdIHx8IHt9O1xuXG4gICAgICBjb25zdCBpc0NsdXN0ZXIgPVxuICAgICAgICAoKGFwaSB8fCB7fSkuY2x1c3Rlcl9pbmZvIHx8IHt9KS5zdGF0dXMgPT09ICdlbmFibGVkJyAmJlxuICAgICAgICB0eXBlb2YgZGFlbW9uc1snd2F6dWgtY2x1c3RlcmQnXSAhPT0gJ3VuZGVmaW5lZCc7XG4gICAgICBjb25zdCB3YXp1aGRiRXhpc3RzID0gdHlwZW9mIGRhZW1vbnNbJ3dhenVoLWRiJ10gIT09ICd1bmRlZmluZWQnO1xuXG4gICAgICBjb25zdCBleGVjZCA9IGRhZW1vbnNbJ3dhenVoLWV4ZWNkJ10gPT09ICdydW5uaW5nJztcbiAgICAgIGNvbnN0IG1vZHVsZXNkID0gZGFlbW9uc1snd2F6dWgtbW9kdWxlc2QnXSA9PT0gJ3J1bm5pbmcnO1xuICAgICAgY29uc3Qgd2F6dWhkYiA9IHdhenVoZGJFeGlzdHMgPyBkYWVtb25zWyd3YXp1aC1kYiddID09PSAncnVubmluZycgOiB0cnVlO1xuICAgICAgY29uc3QgY2x1c3RlcmQgPSBpc0NsdXN0ZXIgPyBkYWVtb25zWyd3YXp1aC1jbHVzdGVyZCddID09PSAncnVubmluZycgOiB0cnVlO1xuXG4gICAgICBjb25zdCBpc1ZhbGlkID0gZXhlY2QgJiYgbW9kdWxlc2QgJiYgd2F6dWhkYiAmJiBjbHVzdGVyZDtcblxuICAgICAgaXNWYWxpZCAmJiBsb2coJ3dhenVoLWFwaTpjaGVja0RhZW1vbnMnLCBgV2F6dWggaXMgcmVhZHlgLCAnZGVidWcnKTtcblxuICAgICAgaWYgKHBhdGggPT09ICcvcGluZycpIHtcbiAgICAgICAgcmV0dXJuIHsgaXNWYWxpZCB9O1xuICAgICAgfVxuXG4gICAgICBpZiAoIWlzVmFsaWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdXYXp1aCBub3QgcmVhZHkgeWV0Jyk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmNoZWNrRGFlbW9ucycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICBzbGVlcCh0aW1lTXMpIHtcbiAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmVcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgc2V0VGltZW91dChyZXNvbHZlLCB0aW1lTXMpO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIEhlbHBlciBtZXRob2QgZm9yIERldiBUb29scy5cbiAgICogaHR0cHM6Ly9kb2N1bWVudGF0aW9uLndhenVoLmNvbS9jdXJyZW50L3VzZXItbWFudWFsL2FwaS9yZWZlcmVuY2UuaHRtbFxuICAgKiBEZXBlbmRpbmcgb24gdGhlIG1ldGhvZCBhbmQgdGhlIHBhdGggc29tZSBwYXJhbWV0ZXJzIHNob3VsZCBiZSBhbiBhcnJheSBvciBub3QuXG4gICAqIFNpbmNlIHdlIGFsbG93IHRoZSB1c2VyIHRvIHdyaXRlIHRoZSByZXF1ZXN0IHVzaW5nIGJvdGggY29tbWEtc2VwYXJhdGVkIGFuZCBhcnJheSBhcyB3ZWxsLFxuICAgKiB3ZSBuZWVkIHRvIGNoZWNrIGlmIGl0IHNob3VsZCBiZSB0cmFuc2Zvcm1lZCBvciBub3QuXG4gICAqIEBwYXJhbSB7Kn0gbWV0aG9kIFRoZSByZXF1ZXN0IG1ldGhvZFxuICAgKiBAcGFyYW0geyp9IHBhdGggVGhlIFdhenVoIEFQSSBwYXRoXG4gICAqL1xuICBzaG91bGRLZWVwQXJyYXlBc0l0KG1ldGhvZCwgcGF0aCkge1xuICAgIC8vIE1ldGhvZHMgdGhhdCB3ZSBtdXN0IHJlc3BlY3QgYSBkbyBub3QgdHJhbnNmb3JtIHRoZW1cbiAgICBjb25zdCBpc0FnZW50c1Jlc3RhcnQgPSBtZXRob2QgPT09ICdQT1NUJyAmJiBwYXRoID09PSAnL2FnZW50cy9yZXN0YXJ0JztcbiAgICBjb25zdCBpc0FjdGl2ZVJlc3BvbnNlID0gbWV0aG9kID09PSAnUFVUJyAmJiBwYXRoLnN0YXJ0c1dpdGgoJy9hY3RpdmUtcmVzcG9uc2UnKTtcbiAgICBjb25zdCBpc0FkZGluZ0FnZW50c1RvR3JvdXAgPSBtZXRob2QgPT09ICdQT1NUJyAmJiBwYXRoLnN0YXJ0c1dpdGgoJy9hZ2VudHMvZ3JvdXAvJyk7XG5cbiAgICAvLyBSZXR1cm5zIHRydWUgb25seSBpZiBvbmUgb2YgdGhlIGFib3ZlIGNvbmRpdGlvbnMgaXMgdHJ1ZVxuICAgIHJldHVybiBpc0FnZW50c1Jlc3RhcnQgfHwgaXNBY3RpdmVSZXNwb25zZSB8fCBpc0FkZGluZ0FnZW50c1RvR3JvdXA7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBwZXJmb3JtcyBhIHJlcXVlc3Qgb3ZlciBXYXp1aCBBUEkgYW5kIHJldHVybnMgaXRzIHJlc3BvbnNlXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBtZXRob2QgTWV0aG9kOiBHRVQsIFBVVCwgUE9TVCwgREVMRVRFXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwYXRoIEFQSSByb3V0ZVxuICAgKiBAcGFyYW0ge09iamVjdH0gZGF0YSBkYXRhIGFuZCBwYXJhbXMgdG8gcGVyZm9ybSB0aGUgcmVxdWVzdFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWQgQVBJIGlkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBBUEkgcmVzcG9uc2Ugb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgbWFrZVJlcXVlc3QoY29udGV4dCwgbWV0aG9kLCBwYXRoLCBkYXRhLCBpZCwgcmVzcG9uc2UpIHtcblxuICAgIGNvbnN0IGRldlRvb2xzID0gISEoZGF0YSB8fCB7fSkuZGV2VG9vbHM7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGFwaSA9IGF3YWl0IHRoaXMubWFuYWdlSG9zdHMuZ2V0SG9zdEJ5SWQoaWQpO1xuICAgICAgaWYgKGRldlRvb2xzKSB7XG4gICAgICAgIGRlbGV0ZSBkYXRhLmRldlRvb2xzO1xuICAgICAgfVxuXG4gICAgICBpZiAoIU9iamVjdC5rZXlzKGFwaSkubGVuZ3RoKSB7XG4gICAgICAgIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgJ0NvdWxkIG5vdCBnZXQgaG9zdCBjcmVkZW50aWFscycpO1xuICAgICAgICAvL0NhbiBub3QgZ2V0IGNyZWRlbnRpYWxzIGZyb20gd2F6dWgtaG9zdHNcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ0NvdWxkIG5vdCBnZXQgaG9zdCBjcmVkZW50aWFscycsIDMwMTEsIEhUVFBfU1RBVFVTX0NPREVTLk5PVF9GT1VORCwgcmVzcG9uc2UpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIWRhdGEpIHtcbiAgICAgICAgZGF0YSA9IHt9O1xuICAgICAgfTtcblxuICAgICAgaWYgKCFkYXRhLmhlYWRlcnMpIHtcbiAgICAgICAgZGF0YS5oZWFkZXJzID0ge307XG4gICAgICB9O1xuXG4gICAgICBjb25zdCBvcHRpb25zID0ge1xuICAgICAgICBhcGlIb3N0SUQ6IGlkXG4gICAgICB9O1xuXG4gICAgICAvLyBTZXQgY29udGVudCB0eXBlIGFwcGxpY2F0aW9uL3htbCBpZiBuZWVkZWRcbiAgICAgIGlmICh0eXBlb2YgKGRhdGEgfHwge30pLmJvZHkgPT09ICdzdHJpbmcnICYmIChkYXRhIHx8IHt9KS5vcmlnaW4gPT09ICd4bWxlZGl0b3InKSB7XG4gICAgICAgIGRhdGEuaGVhZGVyc1snY29udGVudC10eXBlJ10gPSAnYXBwbGljYXRpb24veG1sJztcbiAgICAgICAgZGVsZXRlIGRhdGEub3JpZ2luO1xuICAgICAgfVxuXG4gICAgICBpZiAodHlwZW9mIChkYXRhIHx8IHt9KS5ib2R5ID09PSAnc3RyaW5nJyAmJiAoZGF0YSB8fCB7fSkub3JpZ2luID09PSAnanNvbicpIHtcbiAgICAgICAgZGF0YS5oZWFkZXJzWydjb250ZW50LXR5cGUnXSA9ICdhcHBsaWNhdGlvbi9qc29uJztcbiAgICAgICAgZGVsZXRlIGRhdGEub3JpZ2luO1xuICAgICAgfVxuXG4gICAgICBpZiAodHlwZW9mIChkYXRhIHx8IHt9KS5ib2R5ID09PSAnc3RyaW5nJyAmJiAoZGF0YSB8fCB7fSkub3JpZ2luID09PSAncmF3Jykge1xuICAgICAgICBkYXRhLmhlYWRlcnNbJ2NvbnRlbnQtdHlwZSddID0gJ2FwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSc7XG4gICAgICAgIGRlbGV0ZSBkYXRhLm9yaWdpbjtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGRlbGF5ID0gKGRhdGEgfHwge30pLmRlbGF5IHx8IDA7XG4gICAgICBpZiAoZGVsYXkpIHtcbiAgICAgICAgYWRkSm9iVG9RdWV1ZSh7XG4gICAgICAgICAgc3RhcnRBdDogbmV3IERhdGUoRGF0ZS5ub3coKSArIGRlbGF5KSxcbiAgICAgICAgICBydW46IGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRyeXtcbiAgICAgICAgICAgICAgYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChtZXRob2QsIHBhdGgsIGRhdGEsIG9wdGlvbnMpO1xuICAgICAgICAgICAgfWNhdGNoKGVycm9yKXtcbiAgICAgICAgICAgICAgbG9nKCdxdWV1ZTpkZWxheUFwaVJlcXVlc3QnLGBBbiBlcnJvciBvY3VycmVkIGluIHRoZSBkZWxheWVkIHJlcXVlc3Q6IFwiJHttZXRob2R9ICR7cGF0aH1cIjogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWApO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHsgZXJyb3I6IDAsIG1lc3NhZ2U6ICdTdWNjZXNzJyB9XG4gICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICBpZiAocGF0aCA9PT0gJy9waW5nJykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGNvbnN0IGNoZWNrID0gYXdhaXQgdGhpcy5jaGVja0RhZW1vbnMoY29udGV4dCwgYXBpLCBwYXRoKTtcbiAgICAgICAgICByZXR1cm4gY2hlY2s7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgY29uc3QgaXNEb3duID0gKGVycm9yIHx8IHt9KS5jb2RlID09PSAnRUNPTk5SRUZVU0VEJztcbiAgICAgICAgICBpZiAoIWlzRG93bikge1xuICAgICAgICAgICAgbG9nKCd3YXp1aC1hcGk6bWFrZVJlcXVlc3QnLCAnV2F6dWggQVBJIGlzIG9ubGluZSBidXQgV2F6dWggaXMgbm90IHJlYWR5IHlldCcpO1xuICAgICAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgICAgIGBFUlJPUjMwOTkgLSAke2Vycm9yLm1lc3NhZ2UgfHwgJ1dhenVoIG5vdCByZWFkeSB5ZXQnfWAsXG4gICAgICAgICAgICAgIDMwOTksXG4gICAgICAgICAgICAgIEhUVFBfU1RBVFVTX0NPREVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgYCR7bWV0aG9kfSAke3BhdGh9YCwgJ2RlYnVnJyk7XG5cbiAgICAgIC8vIEV4dHJhY3Qga2V5cyBmcm9tIHBhcmFtZXRlcnNcbiAgICAgIGNvbnN0IGRhdGFQcm9wZXJ0aWVzID0gT2JqZWN0LmtleXMoZGF0YSk7XG5cbiAgICAgIC8vIFRyYW5zZm9ybSBhcnJheXMgaW50byBjb21tYS1zZXBhcmF0ZWQgc3RyaW5nIGlmIGFwcGxpY2FibGUuXG4gICAgICAvLyBUaGUgcmVhc29uIGlzIHRoYXQgd2UgYXJlIGFjY2VwdGluZyBhcnJheXMgZm9yIGNvbW1hLXNlcGFyYXRlZFxuICAgICAgLy8gcGFyYW1ldGVycyBpbiB0aGUgRGV2IFRvb2xzXG4gICAgICBpZiAoIXRoaXMuc2hvdWxkS2VlcEFycmF5QXNJdChtZXRob2QsIHBhdGgpKSB7XG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIGRhdGFQcm9wZXJ0aWVzKSB7XG4gICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoZGF0YVtrZXldKSkge1xuICAgICAgICAgICAgZGF0YVtrZXldID0gZGF0YVtrZXldLmpvaW4oKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgY29uc3QgcmVzcG9uc2VUb2tlbiA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QobWV0aG9kLCBwYXRoLCBkYXRhLCBvcHRpb25zKTtcbiAgICAgIGNvbnN0IHJlc3BvbnNlSXNEb3duID0gdGhpcy5jaGVja1Jlc3BvbnNlSXNEb3duKHJlc3BvbnNlVG9rZW4pO1xuICAgICAgaWYgKHJlc3BvbnNlSXNEb3duKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgIGBFUlJPUjMwOTkgLSAke3Jlc3BvbnNlLmJvZHkubWVzc2FnZSB8fCAnV2F6dWggbm90IHJlYWR5IHlldCd9YCxcbiAgICAgICAgICAzMDk5LFxuICAgICAgICAgIEhUVFBfU1RBVFVTX0NPREVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICAgICByZXNwb25zZVxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgbGV0IHJlc3BvbnNlQm9keSA9IChyZXNwb25zZVRva2VuIHx8IHt9KS5kYXRhIHx8IHt9O1xuICAgICAgaWYgKCFyZXNwb25zZUJvZHkpIHtcbiAgICAgICAgcmVzcG9uc2VCb2R5ID1cbiAgICAgICAgICB0eXBlb2YgcmVzcG9uc2VCb2R5ID09PSAnc3RyaW5nJyAmJiBwYXRoLmluY2x1ZGVzKCcvZmlsZXMnKSAmJiBtZXRob2QgPT09ICdHRVQnXG4gICAgICAgICAgICA/ICcgJ1xuICAgICAgICAgICAgOiBmYWxzZTtcbiAgICAgICAgcmVzcG9uc2UuZGF0YSA9IHJlc3BvbnNlQm9keTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHJlc3BvbnNlRXJyb3IgPSByZXNwb25zZS5zdGF0dXMgIT09IEhUVFBfU1RBVFVTX0NPREVTLk9LID8gcmVzcG9uc2Uuc3RhdHVzIDogZmFsc2U7XG5cbiAgICAgIGlmICghcmVzcG9uc2VFcnJvciAmJiByZXNwb25zZUJvZHkpIHtcbiAgICAgICAgLy9jbGVhbktleXMocmVzcG9uc2UpO1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHJlc3BvbnNlVG9rZW4uZGF0YVxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgaWYgKHJlc3BvbnNlRXJyb3IgJiYgZGV2VG9vbHMpIHtcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiByZXNwb25zZS5kYXRhXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgdGhyb3cgcmVzcG9uc2VFcnJvciAmJiByZXNwb25zZUJvZHkuZGV0YWlsXG4gICAgICAgID8geyBtZXNzYWdlOiByZXNwb25zZUJvZHkuZGV0YWlsLCBjb2RlOiByZXNwb25zZUVycm9yIH1cbiAgICAgICAgOiBuZXcgRXJyb3IoJ1VuZXhwZWN0ZWQgZXJyb3IgZmV0Y2hpbmcgZGF0YSBmcm9tIHRoZSBXYXp1aCBBUEknKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgaWYgKGVycm9yICYmIGVycm9yLnJlc3BvbnNlICYmIGVycm9yLnJlc3BvbnNlLnN0YXR1cyA9PT0gSFRUUF9TVEFUVVNfQ09ERVMuVU5BVVRIT1JJWkVEKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAgIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsXG4gICAgICAgICAgZXJyb3IuY29kZSA/IGBXYXp1aCBBUEkgZXJyb3I6ICR7ZXJyb3IuY29kZX1gIDogMzAxMyxcbiAgICAgICAgICBIVFRQX1NUQVRVU19DT0RFUy5VTkFVVEhPUklaRUQsXG4gICAgICAgICAgcmVzcG9uc2VcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGVycm9yTXNnID0gKGVycm9yLnJlc3BvbnNlIHx8IHt9KS5kYXRhIHx8IGVycm9yLm1lc3NhZ2VcbiAgICAgIGxvZygnd2F6dWgtYXBpOm1ha2VSZXF1ZXN0JywgZXJyb3JNc2cgfHwgZXJyb3IpO1xuICAgICAgaWYgKGRldlRvb2xzKSB7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keTogeyBlcnJvcjogJzMwMTMnLCBtZXNzYWdlOiBlcnJvck1zZyB8fCBlcnJvciB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKChlcnJvciB8fCB7fSkuY29kZSAmJiBBcGlFcnJvckVxdWl2YWxlbmNlW2Vycm9yLmNvZGVdKSB7XG4gICAgICAgICAgZXJyb3IubWVzc2FnZSA9IEFwaUVycm9yRXF1aXZhbGVuY2VbZXJyb3IuY29kZV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgICAgZXJyb3JNc2cuZGV0YWlsIHx8IGVycm9yLFxuICAgICAgICAgIGVycm9yLmNvZGUgPyBgV2F6dWggQVBJIGVycm9yOiAke2Vycm9yLmNvZGV9YCA6IDMwMTMsXG4gICAgICAgICAgSFRUUF9TVEFUVVNfQ09ERVMuSU5URVJOQUxfU0VSVkVSX0VSUk9SLFxuICAgICAgICAgIHJlc3BvbnNlXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgbWFrZSBhIHJlcXVlc3QgdG8gQVBJXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBhcGkgcmVzcG9uc2Ugb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgcmVxdWVzdEFwaShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG5cbiAgICBjb25zdCBpZEFwaSA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei1hcGknKTtcbiAgICBpZiAoaWRBcGkgIT09IHJlcXVlc3QuYm9keS5pZCkgeyAvLyBpZiB0aGUgY3VycmVudCB0b2tlbiBiZWxvbmdzIHRvIGEgZGlmZmVyZW50IEFQSSBpZCwgd2UgcmVsb2dpbiB0byBvYnRhaW4gYSBuZXcgdG9rZW5cbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICAnc3RhdHVzIGNvZGUgNDAxJyxcbiAgICAgICAgSFRUUF9TVEFUVVNfQ09ERVMuVU5BVVRIT1JJWkVELFxuICAgICAgICBIVFRQX1NUQVRVU19DT0RFUy5VTkFVVEhPUklaRUQsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgICBpZiAoIXJlcXVlc3QuYm9keS5tZXRob2QpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdNaXNzaW5nIHBhcmFtOiBtZXRob2QnLCAzMDE1LCBIVFRQX1NUQVRVU19DT0RFUy5CQURfUkVRVUVTVCwgcmVzcG9uc2UpO1xuICAgIH0gZWxzZSBpZiAoIXJlcXVlc3QuYm9keS5tZXRob2QubWF0Y2goL14oPzpHRVR8UFVUfFBPU1R8REVMRVRFKSQvKSkge1xuICAgICAgbG9nKCd3YXp1aC1hcGk6bWFrZVJlcXVlc3QnLCAnUmVxdWVzdCBtZXRob2QgaXMgbm90IHZhbGlkLicpO1xuICAgICAgLy9NZXRob2QgaXMgbm90IGEgdmFsaWQgSFRUUCByZXF1ZXN0IG1ldGhvZFxuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ1JlcXVlc3QgbWV0aG9kIGlzIG5vdCB2YWxpZC4nLCAzMDE1LCBIVFRQX1NUQVRVU19DT0RFUy5CQURfUkVRVUVTVCwgcmVzcG9uc2UpO1xuICAgIH0gZWxzZSBpZiAoIXJlcXVlc3QuYm9keS5wYXRoKSB7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTWlzc2luZyBwYXJhbTogcGF0aCcsIDMwMTYsIEhUVFBfU1RBVFVTX0NPREVTLkJBRF9SRVFVRVNULCByZXNwb25zZSk7XG4gICAgfSBlbHNlIGlmICghcmVxdWVzdC5ib2R5LnBhdGguc3RhcnRzV2l0aCgnLycpKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTptYWtlUmVxdWVzdCcsICdSZXF1ZXN0IHBhdGggaXMgbm90IHZhbGlkLicpO1xuICAgICAgLy9QYXRoIGRvZXNuJ3Qgc3RhcnQgd2l0aCAnLydcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdSZXF1ZXN0IHBhdGggaXMgbm90IHZhbGlkLicsIDMwMTUsIEhUVFBfU1RBVFVTX0NPREVTLkJBRF9SRVFVRVNULCByZXNwb25zZSk7XG4gICAgfSBlbHNlIHtcblxuICAgICAgcmV0dXJuIHRoaXMubWFrZVJlcXVlc3QoXG4gICAgICAgIGNvbnRleHQsXG4gICAgICAgIHJlcXVlc3QuYm9keS5tZXRob2QsXG4gICAgICAgIHJlcXVlc3QuYm9keS5wYXRoLFxuICAgICAgICByZXF1ZXN0LmJvZHkuYm9keSxcbiAgICAgICAgcmVxdWVzdC5ib2R5LmlkLFxuICAgICAgICByZXNwb25zZVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogR2V0IGZ1bGwgZGF0YSBvbiBDU1YgZm9ybWF0IGZyb20gYSBsaXN0IFdhenVoIEFQSSBlbmRwb2ludFxuICAgKiBAcGFyYW0ge09iamVjdH0gY3R4XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBjc3Ygb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgY3N2KGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCFyZXF1ZXN0LmJvZHkgfHwgIXJlcXVlc3QuYm9keS5wYXRoKSB0aHJvdyBuZXcgRXJyb3IoJ0ZpZWxkIHBhdGggaXMgcmVxdWlyZWQnKTtcbiAgICAgIGlmICghcmVxdWVzdC5ib2R5LmlkKSB0aHJvdyBuZXcgRXJyb3IoJ0ZpZWxkIGlkIGlzIHJlcXVpcmVkJyk7XG5cbiAgICAgIGNvbnN0IGZpbHRlcnMgPSBBcnJheS5pc0FycmF5KCgocmVxdWVzdCB8fCB7fSkuYm9keSB8fCB7fSkuZmlsdGVycykgPyByZXF1ZXN0LmJvZHkuZmlsdGVycyA6IFtdO1xuXG4gICAgICBsZXQgdG1wUGF0aCA9IHJlcXVlc3QuYm9keS5wYXRoO1xuXG4gICAgICBpZiAodG1wUGF0aCAmJiB0eXBlb2YgdG1wUGF0aCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgdG1wUGF0aCA9IHRtcFBhdGhbMF0gPT09ICcvJyA/IHRtcFBhdGguc3Vic3RyKDEpIDogdG1wUGF0aDtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0bXBQYXRoKSB0aHJvdyBuZXcgRXJyb3IoJ0FuIGVycm9yIG9jY3VycmVkIHBhcnNpbmcgcGF0aCBmaWVsZCcpO1xuXG4gICAgICBsb2coJ3dhenVoLWFwaTpjc3YnLCBgUmVwb3J0ICR7dG1wUGF0aH1gLCAnZGVidWcnKTtcbiAgICAgIC8vIFJlYWwgbGltaXQsIHJlZ2FyZGxlc3MgdGhlIHVzZXIgcXVlcnlcbiAgICAgIGNvbnN0IHBhcmFtcyA9IHsgbGltaXQ6IDUwMCB9O1xuXG4gICAgICBpZiAoZmlsdGVycy5sZW5ndGgpIHtcbiAgICAgICAgZm9yIChjb25zdCBmaWx0ZXIgb2YgZmlsdGVycykge1xuICAgICAgICAgIGlmICghZmlsdGVyLm5hbWUgfHwgIWZpbHRlci52YWx1ZSkgY29udGludWU7XG4gICAgICAgICAgcGFyYW1zW2ZpbHRlci5uYW1lXSA9IGZpbHRlci52YWx1ZTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBsZXQgaXRlbXNBcnJheSA9IFtdO1xuXG4gICAgICBjb25zdCBvdXRwdXQgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAnR0VUJyxcbiAgICAgICAgYC8ke3RtcFBhdGh9YCxcbiAgICAgICAgeyBwYXJhbXM6IHBhcmFtcyB9LFxuICAgICAgICB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH1cbiAgICAgICk7XG5cbiAgICAgIGNvbnN0IGlzTGlzdCA9IHJlcXVlc3QuYm9keS5wYXRoLmluY2x1ZGVzKCcvbGlzdHMnKSAmJiByZXF1ZXN0LmJvZHkuZmlsdGVycyAmJiByZXF1ZXN0LmJvZHkuZmlsdGVycy5sZW5ndGggJiYgcmVxdWVzdC5ib2R5LmZpbHRlcnMuZmluZChmaWx0ZXIgPT4gZmlsdGVyLl9pc0NEQkxpc3QpO1xuXG4gICAgICBjb25zdCB0b3RhbEl0ZW1zID0gKCgob3V0cHV0IHx8IHt9KS5kYXRhIHx8IHt9KS5kYXRhIHx8IHt9KS50b3RhbF9hZmZlY3RlZF9pdGVtcztcblxuICAgICAgaWYgKHRvdGFsSXRlbXMgJiYgIWlzTGlzdCkge1xuICAgICAgICBwYXJhbXMub2Zmc2V0ID0gMDtcbiAgICAgICAgaXRlbXNBcnJheS5wdXNoKC4uLm91dHB1dC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXMpO1xuICAgICAgICB3aGlsZSAoaXRlbXNBcnJheS5sZW5ndGggPCB0b3RhbEl0ZW1zICYmIHBhcmFtcy5vZmZzZXQgPCB0b3RhbEl0ZW1zKSB7XG4gICAgICAgICAgcGFyYW1zLm9mZnNldCArPSBwYXJhbXMubGltaXQ7XG4gICAgICAgICAgY29uc3QgdG1wRGF0YSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgIGAvJHt0bXBQYXRofWAsXG4gICAgICAgICAgICB7IHBhcmFtczogcGFyYW1zIH0sXG4gICAgICAgICAgICB7IGFwaUhvc3RJRDogcmVxdWVzdC5ib2R5LmlkIH1cbiAgICAgICAgICApO1xuICAgICAgICAgIGl0ZW1zQXJyYXkucHVzaCguLi50bXBEYXRhLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtcyk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHRvdGFsSXRlbXMpIHtcbiAgICAgICAgY29uc3QgeyBwYXRoLCBmaWx0ZXJzIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICAgIGNvbnN0IGlzQXJyYXlPZkxpc3RzID1cbiAgICAgICAgICBwYXRoLmluY2x1ZGVzKCcvbGlzdHMnKSAmJiAhaXNMaXN0O1xuICAgICAgICBjb25zdCBpc0FnZW50cyA9IHBhdGguaW5jbHVkZXMoJy9hZ2VudHMnKSAmJiAhcGF0aC5pbmNsdWRlcygnZ3JvdXBzJyk7XG4gICAgICAgIGNvbnN0IGlzQWdlbnRzT2ZHcm91cCA9IHBhdGguc3RhcnRzV2l0aCgnL2FnZW50cy9ncm91cHMvJyk7XG4gICAgICAgIGNvbnN0IGlzRmlsZXMgPSBwYXRoLmVuZHNXaXRoKCcvZmlsZXMnKTtcbiAgICAgICAgbGV0IGZpZWxkcyA9IE9iamVjdC5rZXlzKG91dHB1dC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0pO1xuXG4gICAgICAgIGlmIChpc0FnZW50cyB8fCBpc0FnZW50c09mR3JvdXApIHtcbiAgICAgICAgICBpZiAoaXNGaWxlcykge1xuICAgICAgICAgICAgZmllbGRzID0gWydmaWxlbmFtZScsICdoYXNoJ107XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGZpZWxkcyA9IFtcbiAgICAgICAgICAgICAgJ2lkJyxcbiAgICAgICAgICAgICAgJ3N0YXR1cycsXG4gICAgICAgICAgICAgICduYW1lJyxcbiAgICAgICAgICAgICAgJ2lwJyxcbiAgICAgICAgICAgICAgJ2dyb3VwJyxcbiAgICAgICAgICAgICAgJ21hbmFnZXInLFxuICAgICAgICAgICAgICAnbm9kZV9uYW1lJyxcbiAgICAgICAgICAgICAgJ2RhdGVBZGQnLFxuICAgICAgICAgICAgICAndmVyc2lvbicsXG4gICAgICAgICAgICAgICdsYXN0S2VlcEFsaXZlJyxcbiAgICAgICAgICAgICAgJ29zLmFyY2gnLFxuICAgICAgICAgICAgICAnb3MuYnVpbGQnLFxuICAgICAgICAgICAgICAnb3MuY29kZW5hbWUnLFxuICAgICAgICAgICAgICAnb3MubWFqb3InLFxuICAgICAgICAgICAgICAnb3MubWlub3InLFxuICAgICAgICAgICAgICAnb3MubmFtZScsXG4gICAgICAgICAgICAgICdvcy5wbGF0Zm9ybScsXG4gICAgICAgICAgICAgICdvcy51bmFtZScsXG4gICAgICAgICAgICAgICdvcy52ZXJzaW9uJyxcbiAgICAgICAgICAgIF07XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGlzQXJyYXlPZkxpc3RzKSB7XG4gICAgICAgICAgY29uc3QgZmxhdExpc3RzID0gW107XG4gICAgICAgICAgZm9yIChjb25zdCBsaXN0IG9mIGl0ZW1zQXJyYXkpIHtcbiAgICAgICAgICAgIGNvbnN0IHsgcmVsYXRpdmVfZGlybmFtZSwgaXRlbXMgfSA9IGxpc3Q7XG4gICAgICAgICAgICBmbGF0TGlzdHMucHVzaCguLi5pdGVtcy5tYXAoaXRlbSA9PiAoeyByZWxhdGl2ZV9kaXJuYW1lLCBrZXk6IGl0ZW0ua2V5LCB2YWx1ZTogaXRlbS52YWx1ZSB9KSkpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBmaWVsZHMgPSBbJ3JlbGF0aXZlX2Rpcm5hbWUnLCAna2V5JywgJ3ZhbHVlJ107XG4gICAgICAgICAgaXRlbXNBcnJheSA9IFsuLi5mbGF0TGlzdHNdO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGlzTGlzdCkge1xuICAgICAgICAgIGZpZWxkcyA9IFsna2V5JywgJ3ZhbHVlJ107XG4gICAgICAgICAgaXRlbXNBcnJheSA9IG91dHB1dC5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0uaXRlbXM7XG4gICAgICAgIH1cbiAgICAgICAgZmllbGRzID0gZmllbGRzLm1hcChpdGVtID0+ICh7IHZhbHVlOiBpdGVtLCBkZWZhdWx0OiAnLScgfSkpO1xuXG4gICAgICAgIGNvbnN0IGpzb24yY3N2UGFyc2VyID0gbmV3IFBhcnNlcih7IGZpZWxkcyB9KTtcblxuICAgICAgICBsZXQgY3N2ID0ganNvbjJjc3ZQYXJzZXIucGFyc2UoaXRlbXNBcnJheSk7XG4gICAgICAgIGZvciAoY29uc3QgZmllbGQgb2YgZmllbGRzKSB7XG4gICAgICAgICAgY29uc3QgeyB2YWx1ZSB9ID0gZmllbGQ7XG4gICAgICAgICAgaWYgKGNzdi5pbmNsdWRlcyh2YWx1ZSkpIHtcbiAgICAgICAgICAgIGNzdiA9IGNzdi5yZXBsYWNlKHZhbHVlLCBLZXlFcXVpdmFsZW5jZVt2YWx1ZV0gfHwgdmFsdWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ3RleHQvY3N2JyB9LFxuICAgICAgICAgIGJvZHk6IGNzdlxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSBpZiAob3V0cHV0ICYmIG91dHB1dC5kYXRhICYmIG91dHB1dC5kYXRhLmRhdGEgJiYgIW91dHB1dC5kYXRhLmRhdGEudG90YWxfYWZmZWN0ZWRfaXRlbXMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdObyByZXN1bHRzJyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEFuIGVycm9yIG9jY3VycmVkIGZldGNoaW5nIGRhdGEgZnJvbSB0aGUgV2F6dWggQVBJJHtvdXRwdXQgJiYgb3V0cHV0LmRhdGEgJiYgb3V0cHV0LmRhdGEuZGV0YWlsID8gYDogJHtvdXRwdXQuYm9keS5kZXRhaWx9YCA6ICcnfWApO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpjc3YnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDMwMzQsIEhUVFBfU1RBVFVTX0NPREVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUiwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8vIEdldCBkZSBsaXN0IG9mIGF2YWlsYWJsZSByZXF1ZXN0cyBpbiB0aGUgQVBJXG4gIGdldFJlcXVlc3RMaXN0KGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICAvL1JlYWQgYSBzdGF0aWMgSlNPTiB1bnRpbCB0aGUgYXBpIGNhbGwgaGFzIGltcGxlbWVudGVkXG4gICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgIGJvZHk6IGFwaVJlcXVlc3RMaXN0XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBnZXQgdGhlIHRpbWVzdGFtcCBmaWVsZFxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gdGltZXN0YW1wIGZpZWxkIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGdldFRpbWVTdGFtcChjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHNvdXJjZSA9IEpTT04ucGFyc2UoZnMucmVhZEZpbGVTeW5jKHRoaXMudXBkYXRlUmVnaXN0cnkuZmlsZSwgJ3V0ZjgnKSk7XG4gICAgICBpZiAoc291cmNlLmluc3RhbGxhdGlvbkRhdGUgJiYgc291cmNlLmxhc3RSZXN0YXJ0KSB7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAnd2F6dWgtYXBpOmdldFRpbWVTdGFtcCcsXG4gICAgICAgICAgYEluc3RhbGxhdGlvbiBkYXRlOiAke3NvdXJjZS5pbnN0YWxsYXRpb25EYXRlfS4gTGFzdCByZXN0YXJ0OiAke3NvdXJjZS5sYXN0UmVzdGFydH1gLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBpbnN0YWxsYXRpb25EYXRlOiBzb3VyY2UuaW5zdGFsbGF0aW9uRGF0ZSxcbiAgICAgICAgICAgIGxhc3RSZXN0YXJ0OiBzb3VyY2UubGFzdFJlc3RhcnQsXG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQ291bGQgbm90IGZldGNoIHdhenVoLXZlcnNpb24gcmVnaXN0cnknKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1hcGk6Z2V0VGltZVN0YW1wJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgZXJyb3IubWVzc2FnZSB8fCAnQ291bGQgbm90IGZldGNoIHdhenVoLXZlcnNpb24gcmVnaXN0cnknLFxuICAgICAgICA0MDAxLFxuICAgICAgICBIVFRQX1NUQVRVU19DT0RFUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGdldCB0aGUgZXh0ZW5zaW9uc1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gZXh0ZW5zaW9ucyBvYmplY3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgc2V0RXh0ZW5zaW9ucyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQsIGV4dGVuc2lvbnMgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIC8vIFVwZGF0ZSBjbHVzdGVyIGluZm9ybWF0aW9uIGluIHRoZSB3YXp1aC1yZWdpc3RyeS5qc29uXG4gICAgICBhd2FpdCB0aGlzLnVwZGF0ZVJlZ2lzdHJ5LnVwZGF0ZUFQSUV4dGVuc2lvbnMoaWQsIGV4dGVuc2lvbnMpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN0YXR1c0NvZGU6IEhUVFBfU1RBVFVTX0NPREVTLk9LXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpzZXRFeHRlbnNpb25zJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgZXJyb3IubWVzc2FnZSB8fCAnQ291bGQgbm90IHNldCBleHRlbnNpb25zJyxcbiAgICAgICAgNDAwMSxcbiAgICAgICAgSFRUUF9TVEFUVVNfQ09ERVMuSU5URVJOQUxfU0VSVkVSX0VSUk9SLFxuICAgICAgICByZXNwb25zZVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBnZXQgdGhlIGV4dGVuc2lvbnNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IGV4dGVuc2lvbnMgb2JqZWN0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGdldEV4dGVuc2lvbnMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzb3VyY2UgPSBKU09OLnBhcnNlKFxuICAgICAgICBmcy5yZWFkRmlsZVN5bmModGhpcy51cGRhdGVSZWdpc3RyeS5maWxlLCAndXRmOCcpXG4gICAgICApO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIGV4dGVuc2lvbnM6IChzb3VyY2UuaG9zdHNbcmVxdWVzdC5wYXJhbXMuaWRdIHx8IHt9KS5leHRlbnNpb25zIHx8IHt9XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpnZXRFeHRlbnNpb25zJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgZXJyb3IubWVzc2FnZSB8fCAnQ291bGQgbm90IGZldGNoIHdhenVoLXZlcnNpb24gcmVnaXN0cnknLFxuICAgICAgICA0MDAxLFxuICAgICAgICBIVFRQX1NUQVRVU19DT0RFUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGdldCB0aGUgd2F6dWggc2V0dXAgc2V0dGluZ3NcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IHNldHVwIGluZm8gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0U2V0dXBJbmZvKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3Qgc291cmNlID0gSlNPTi5wYXJzZShmcy5yZWFkRmlsZVN5bmModGhpcy51cGRhdGVSZWdpc3RyeS5maWxlLCAndXRmOCcpKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdGF0dXNDb2RlOiBIVFRQX1NUQVRVU19DT0RFUy5PSyxcbiAgICAgICAgICBkYXRhOiAhT2JqZWN0LnZhbHVlcyhzb3VyY2UpLmxlbmd0aCA/ICcnIDogc291cmNlXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWFwaTpnZXRTZXR1cEluZm8nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICBgQ291bGQgbm90IGdldCBkYXRhIGZyb20gd2F6dWgtdmVyc2lvbiByZWdpc3RyeSBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsXG4gICAgICAgIDQwMDUsXG4gICAgICAgIEhUVFBfU1RBVFVTX0NPREVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEdldCBiYXNpYyBzeXNjb2xsZWN0b3IgaW5mb3JtYXRpb24gZm9yIGdpdmVuIGFnZW50LlxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gQmFzaWMgc3lzY29sbGVjdG9yIGluZm9ybWF0aW9uXG4gICAqL1xuICBhc3luYyBnZXRTeXNjb2xsZWN0b3IoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBhcGlIb3N0SUQgPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCd3ei1hcGknKTtcbiAgICAgIGlmICghcmVxdWVzdC5wYXJhbXMgfHwgIWFwaUhvc3RJRCB8fCAhcmVxdWVzdC5wYXJhbXMuYWdlbnQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdBZ2VudCBJRCBhbmQgQVBJIElEIGFyZSByZXF1aXJlZCcpO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB7IGFnZW50IH0gPSByZXF1ZXN0LnBhcmFtcztcblxuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IFByb21pc2UuYWxsKFtcbiAgICAgICAgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoJ0dFVCcsIGAvc3lzY29sbGVjdG9yLyR7YWdlbnR9L2hhcmR3YXJlYCwge30sIHsgYXBpSG9zdElEIH0pLFxuICAgICAgICBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdCgnR0VUJywgYC9zeXNjb2xsZWN0b3IvJHthZ2VudH0vb3NgLCB7fSwgeyBhcGlIb3N0SUQgfSlcbiAgICAgIF0pO1xuXG4gICAgICBjb25zdCByZXN1bHQgPSBkYXRhLm1hcChpdGVtID0+IChpdGVtLmRhdGEgfHwge30pLmRhdGEgfHwgW10pO1xuICAgICAgY29uc3QgW2hhcmR3YXJlUmVzcG9uc2UsIG9zUmVzcG9uc2VdID0gcmVzdWx0O1xuXG4gICAgICAvLyBGaWxsIHN5c2NvbGxlY3RvciBvYmplY3RcbiAgICAgIGNvbnN0IHN5c2NvbGxlY3RvciA9IHtcbiAgICAgICAgaGFyZHdhcmU6XG4gICAgICAgICAgdHlwZW9mIGhhcmR3YXJlUmVzcG9uc2UgPT09ICdvYmplY3QnICYmIE9iamVjdC5rZXlzKGhhcmR3YXJlUmVzcG9uc2UpLmxlbmd0aFxuICAgICAgICAgICAgPyB7IC4uLmhhcmR3YXJlUmVzcG9uc2UuYWZmZWN0ZWRfaXRlbXNbMF0gfVxuICAgICAgICAgICAgOiBmYWxzZSxcbiAgICAgICAgb3M6XG4gICAgICAgICAgdHlwZW9mIG9zUmVzcG9uc2UgPT09ICdvYmplY3QnICYmIE9iamVjdC5rZXlzKG9zUmVzcG9uc2UpLmxlbmd0aFxuICAgICAgICAgICAgPyB7IC4uLm9zUmVzcG9uc2UuYWZmZWN0ZWRfaXRlbXNbMF0gfVxuICAgICAgICAgICAgOiBmYWxzZSxcbiAgICAgIH07XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHN5c2NvbGxlY3RvclxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmdldFN5c2NvbGxlY3RvcicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgMzAzNSwgSFRUUF9TVEFUVVNfQ09ERVMuSU5URVJOQUxfU0VSVkVSX0VSUk9SLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG4gIC8qKlxuICAgKiBDaGVjayBpZiB1c2VyIGFzc2lnbmVkIHJvbGVzIGRpc2FibGUgV2F6dWggUGx1Z2luXG4gICAqIEBwYXJhbSBjb250ZXh0XG4gICAqIEBwYXJhbSByZXF1ZXN0XG4gICAqIEBwYXJhbSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7b2JqZWN0fSBSZXR1cm5zIHsgaXNXYXp1aERpc2FibGVkOiBib29sZWFuIHBhcnNlZCBpbnRlZ2VyIH1cbiAgICovXG4gIGFzeW5jIGlzV2F6dWhEaXNhYmxlZChjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcblxuICAgICAgY29uc3QgZGlzYWJsZWRSb2xlcyA9ICggYXdhaXQgZ2V0Q29uZmlndXJhdGlvbigpIClbJ2Rpc2FibGVkX3JvbGVzJ10gfHwgW107XG4gICAgICBjb25zdCBsb2dvU2lkZWJhciA9ICggYXdhaXQgZ2V0Q29uZmlndXJhdGlvbigpIClbJ2N1c3RvbWl6YXRpb24ubG9nby5zaWRlYmFyJ107XG4gICAgICBjb25zdCBkYXRhID0gKGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCkpLmF1dGhDb250ZXh0O1xuXG4gICAgICBjb25zdCBpc1dhenVoRGlzYWJsZWQgPSArKGRhdGEucm9sZXMgfHwgW10pLnNvbWUoKHJvbGUpID0+IGRpc2FibGVkUm9sZXMuaW5jbHVkZXMocm9sZSkpO1xuXG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IGlzV2F6dWhEaXNhYmxlZCwgbG9nb1NpZGViYXIgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmlzV2F6dWhEaXNhYmxlZCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgMzAzNSwgSFRUUF9TVEFUVVNfQ09ERVMuSU5URVJOQUxfU0VSVkVSX0VSUk9SLCByZXNwb25zZSk7XG4gICAgfVxuXG4gIH1cblxuICAvKipcbiAgICogR2V0cyBjdXN0b20gbG9nb3MgY29uZmlndXJhdGlvbiAocGF0aClcbiAgICogQHBhcmFtIGNvbnRleHRcbiAgICogQHBhcmFtIHJlcXVlc3RcbiAgICogQHBhcmFtIHJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBnZXRBcHBMb2dvcyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGNvbmZpZ3VyYXRpb24gPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgICBjb25zdCBTSURFQkFSX0xPR08gPSAnY3VzdG9taXphdGlvbi5sb2dvLnNpZGViYXInO1xuICAgICAgY29uc3QgQVBQX0xPR08gPSAnY3VzdG9taXphdGlvbi5sb2dvLmFwcCc7XG4gICAgICBjb25zdCBIRUFMVEhDSEVDS19MT0dPID0gJ2N1c3RvbWl6YXRpb24ubG9nby5oZWFsdGhjaGVjayc7XG5cbiAgICAgIGNvbnN0IGxvZ29zPSB7XG4gICAgICAgIFtTSURFQkFSX0xPR09dOiBnZXRDdXN0b21pemF0aW9uU2V0dGluZyhjb25maWd1cmF0aW9uLCBTSURFQkFSX0xPR08pLFxuICAgICAgICBbQVBQX0xPR09dOiBnZXRDdXN0b21pemF0aW9uU2V0dGluZyhjb25maWd1cmF0aW9uLCBBUFBfTE9HTyksXG4gICAgICAgIFtIRUFMVEhDSEVDS19MT0dPXTogZ2V0Q3VzdG9taXphdGlvblNldHRpbmcoY29uZmlndXJhdGlvbiwgSEVBTFRIQ0hFQ0tfTE9HTyksXG4gICAgICB9XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgbG9nb3MgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtYXBpOmdldEFwcExvZ29zJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAzMDM1LCBIVFRQX1NUQVRVU19DT0RFUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsIHJlc3BvbnNlKTtcbiAgICB9XG5cbiAgfVxufVxuIl19