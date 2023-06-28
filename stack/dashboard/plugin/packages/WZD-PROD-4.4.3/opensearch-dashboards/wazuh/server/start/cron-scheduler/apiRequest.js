"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ApiRequest = void 0;

var ApiInterceptor = _interopRequireWildcard(require("../../lib/api-interceptor.js"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class ApiRequest {
  constructor(request, api, params = {}) {
    _defineProperty(this, "api", void 0);

    _defineProperty(this, "request", void 0);

    _defineProperty(this, "params", void 0);

    this.request = request;
    this.api = api;
    this.params = params;
  }

  async makeRequest() {
    const {
      id,
      url,
      port
    } = this.api;
    const response = await ApiInterceptor.requestAsInternalUser('GET', '/${this.request}', this.params, {
      apiHostID: id
    });
    return response;
  }

  async getData() {
    try {
      const response = await this.makeRequest();
      if (response.status !== 200) throw response;
      return response.data;
    } catch (error) {
      if (error.status === 404) {
        throw {
          error: 404,
          message: error.data.detail
        };
      }

      if (error.response && error.response.status === 401) {
        throw {
          error: 401,
          message: 'Wrong Wazuh API credentials used'
        };
      }

      if (error && error.data && error.data.detail && error.data.detail === 'ECONNRESET') {
        throw {
          error: 3005,
          message: 'Wrong protocol being used to connect to the Wazuh API'
        };
      }

      if (error && error.data && error.data.detail && ['ENOTFOUND', 'EHOSTUNREACH', 'EINVAL', 'EAI_AGAIN', 'ECONNREFUSED'].includes(error.data.detail)) {
        throw {
          error: 3005,
          message: 'Wazuh API is not reachable. Please check your url and port.'
        };
      }

      throw error;
    }
  }

}

exports.ApiRequest = ApiRequest;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwaVJlcXVlc3QudHMiXSwibmFtZXMiOlsiQXBpUmVxdWVzdCIsImNvbnN0cnVjdG9yIiwicmVxdWVzdCIsImFwaSIsInBhcmFtcyIsIm1ha2VSZXF1ZXN0IiwiaWQiLCJ1cmwiLCJwb3J0IiwicmVzcG9uc2UiLCJBcGlJbnRlcmNlcHRvciIsInJlcXVlc3RBc0ludGVybmFsVXNlciIsImFwaUhvc3RJRCIsImdldERhdGEiLCJzdGF0dXMiLCJkYXRhIiwiZXJyb3IiLCJtZXNzYWdlIiwiZGV0YWlsIiwiaW5jbHVkZXMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFDQTs7Ozs7Ozs7QUFlTyxNQUFNQSxVQUFOLENBQWlCO0FBS3RCQyxFQUFBQSxXQUFXLENBQUNDLE9BQUQsRUFBaUJDLEdBQWpCLEVBQTJCQyxNQUFTLEdBQUMsRUFBckMsRUFBMkM7QUFBQTs7QUFBQTs7QUFBQTs7QUFDcEQsU0FBS0YsT0FBTCxHQUFlQSxPQUFmO0FBQ0EsU0FBS0MsR0FBTCxHQUFXQSxHQUFYO0FBQ0EsU0FBS0MsTUFBTCxHQUFjQSxNQUFkO0FBQ0Q7O0FBRXdCLFFBQVhDLFdBQVcsR0FBMEI7QUFDakQsVUFBTTtBQUFDQyxNQUFBQSxFQUFEO0FBQUtDLE1BQUFBLEdBQUw7QUFBVUMsTUFBQUE7QUFBVixRQUFrQixLQUFLTCxHQUE3QjtBQUVBLFVBQU1NLFFBQXVCLEdBQUcsTUFBTUMsY0FBYyxDQUFDQyxxQkFBZixDQUNwQyxLQURvQyxFQUVwQyxrQkFGb0MsRUFHcEMsS0FBS1AsTUFIK0IsRUFJcEM7QUFBQ1EsTUFBQUEsU0FBUyxFQUFFTjtBQUFaLEtBSm9DLENBQXRDO0FBTUEsV0FBT0csUUFBUDtBQUNEOztBQUVtQixRQUFQSSxPQUFPLEdBQW1CO0FBQ3JDLFFBQUk7QUFDRixZQUFNSixRQUFRLEdBQUcsTUFBTSxLQUFLSixXQUFMLEVBQXZCO0FBQ0EsVUFBSUksUUFBUSxDQUFDSyxNQUFULEtBQW9CLEdBQXhCLEVBQTZCLE1BQU1MLFFBQU47QUFDN0IsYUFBT0EsUUFBUSxDQUFDTSxJQUFoQjtBQUNELEtBSkQsQ0FJRSxPQUFPQyxLQUFQLEVBQWM7QUFDZCxVQUFJQSxLQUFLLENBQUNGLE1BQU4sS0FBaUIsR0FBckIsRUFBMEI7QUFDeEIsY0FBTTtBQUFDRSxVQUFBQSxLQUFLLEVBQUUsR0FBUjtBQUFhQyxVQUFBQSxPQUFPLEVBQUVELEtBQUssQ0FBQ0QsSUFBTixDQUFXRztBQUFqQyxTQUFOO0FBQ0Q7O0FBQ0QsVUFBSUYsS0FBSyxDQUFDUCxRQUFOLElBQWtCTyxLQUFLLENBQUNQLFFBQU4sQ0FBZUssTUFBZixLQUEwQixHQUFoRCxFQUFvRDtBQUNsRCxjQUFNO0FBQUNFLFVBQUFBLEtBQUssRUFBRSxHQUFSO0FBQWFDLFVBQUFBLE9BQU8sRUFBRTtBQUF0QixTQUFOO0FBQ0Q7O0FBQ0QsVUFBSUQsS0FBSyxJQUFJQSxLQUFLLENBQUNELElBQWYsSUFBdUJDLEtBQUssQ0FBQ0QsSUFBTixDQUFXRyxNQUFsQyxJQUE0Q0YsS0FBSyxDQUFDRCxJQUFOLENBQVdHLE1BQVgsS0FBc0IsWUFBdEUsRUFBb0Y7QUFDbEYsY0FBTTtBQUFDRixVQUFBQSxLQUFLLEVBQUUsSUFBUjtBQUFjQyxVQUFBQSxPQUFPLEVBQUU7QUFBdkIsU0FBTjtBQUNEOztBQUNELFVBQUlELEtBQUssSUFBSUEsS0FBSyxDQUFDRCxJQUFmLElBQXVCQyxLQUFLLENBQUNELElBQU4sQ0FBV0csTUFBbEMsSUFBNEMsQ0FBQyxXQUFELEVBQWEsY0FBYixFQUE0QixRQUE1QixFQUFxQyxXQUFyQyxFQUFpRCxjQUFqRCxFQUFpRUMsUUFBakUsQ0FBMEVILEtBQUssQ0FBQ0QsSUFBTixDQUFXRyxNQUFyRixDQUFoRCxFQUE4STtBQUM1SSxjQUFNO0FBQUNGLFVBQUFBLEtBQUssRUFBRSxJQUFSO0FBQWNDLFVBQUFBLE9BQU8sRUFBRTtBQUF2QixTQUFOO0FBQ0Q7O0FBQ0QsWUFBTUQsS0FBTjtBQUNEO0FBQ0Y7O0FBM0NxQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEF4aW9zUmVzcG9uc2UgfWZyb20gJ2F4aW9zJztcbmltcG9ydCAqIGFzIEFwaUludGVyY2VwdG9yICBmcm9tICcuLi8uLi9saWIvYXBpLWludGVyY2VwdG9yLmpzJztcblxuZXhwb3J0IGludGVyZmFjZSBJQXBpIHtcbiAgaWQ6IHN0cmluZ1xuICB1c2VyOiBzdHJpbmdcbiAgcGFzc3dvcmQ6IHN0cmluZ1xuICB1cmw6IHN0cmluZ1xuICBwb3J0OiBudW1iZXJcbiAgY2x1c3Rlcl9pbmZvOiB7XG4gICAgbWFuYWdlcjogc3RyaW5nXG4gICAgY2x1c3RlcjogJ0Rpc2FibGVkJyB8ICdFbmFibGVkJ1xuICAgIHN0YXR1czogJ2Rpc2FibGVkJyB8ICdlbmFibGVkJ1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBBcGlSZXF1ZXN0IHtcbiAgcHJpdmF0ZSBhcGk6IElBcGk7XG4gIHByaXZhdGUgcmVxdWVzdDogc3RyaW5nO1xuICBwcml2YXRlIHBhcmFtczoge307XG5cbiAgY29uc3RydWN0b3IocmVxdWVzdDpzdHJpbmcsIGFwaTpJQXBpLCBwYXJhbXM6e309e30sICkge1xuICAgIHRoaXMucmVxdWVzdCA9IHJlcXVlc3Q7XG4gICAgdGhpcy5hcGkgPSBhcGk7XG4gICAgdGhpcy5wYXJhbXMgPSBwYXJhbXM7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIG1ha2VSZXF1ZXN0KCk6UHJvbWlzZTxBeGlvc1Jlc3BvbnNlPiB7XG4gICAgY29uc3Qge2lkLCB1cmwsIHBvcnR9ID0gdGhpcy5hcGk7XG4gICAgXG4gICAgY29uc3QgcmVzcG9uc2U6IEF4aW9zUmVzcG9uc2UgPSBhd2FpdCBBcGlJbnRlcmNlcHRvci5yZXF1ZXN0QXNJbnRlcm5hbFVzZXIoXG4gICAgICAnR0VUJyxcbiAgICAgICcvJHt0aGlzLnJlcXVlc3R9JyxcbiAgICAgIHRoaXMucGFyYW1zLFxuICAgICAge2FwaUhvc3RJRDogaWQgfVxuICAgIClcbiAgICByZXR1cm4gcmVzcG9uc2U7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgZ2V0RGF0YSgpOlByb21pc2U8b2JqZWN0PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdGhpcy5tYWtlUmVxdWVzdCgpO1xuICAgICAgaWYgKHJlc3BvbnNlLnN0YXR1cyAhPT0gMjAwKSB0aHJvdyByZXNwb25zZTtcbiAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBpZiAoZXJyb3Iuc3RhdHVzID09PSA0MDQpIHtcbiAgICAgICAgdGhyb3cge2Vycm9yOiA0MDQsIG1lc3NhZ2U6IGVycm9yLmRhdGEuZGV0YWlsfTtcbiAgICAgIH1cbiAgICAgIGlmIChlcnJvci5yZXNwb25zZSAmJiBlcnJvci5yZXNwb25zZS5zdGF0dXMgPT09IDQwMSl7XG4gICAgICAgIHRocm93IHtlcnJvcjogNDAxLCBtZXNzYWdlOiAnV3JvbmcgV2F6dWggQVBJIGNyZWRlbnRpYWxzIHVzZWQnfTtcbiAgICAgIH1cbiAgICAgIGlmIChlcnJvciAmJiBlcnJvci5kYXRhICYmIGVycm9yLmRhdGEuZGV0YWlsICYmIGVycm9yLmRhdGEuZGV0YWlsID09PSAnRUNPTk5SRVNFVCcpIHtcbiAgICAgICAgdGhyb3cge2Vycm9yOiAzMDA1LCBtZXNzYWdlOiAnV3JvbmcgcHJvdG9jb2wgYmVpbmcgdXNlZCB0byBjb25uZWN0IHRvIHRoZSBXYXp1aCBBUEknfTtcbiAgICAgIH1cbiAgICAgIGlmIChlcnJvciAmJiBlcnJvci5kYXRhICYmIGVycm9yLmRhdGEuZGV0YWlsICYmIFsnRU5PVEZPVU5EJywnRUhPU1RVTlJFQUNIJywnRUlOVkFMJywnRUFJX0FHQUlOJywnRUNPTk5SRUZVU0VEJ10uaW5jbHVkZXMoZXJyb3IuZGF0YS5kZXRhaWwpKSB7XG4gICAgICAgIHRocm93IHtlcnJvcjogMzAwNSwgbWVzc2FnZTogJ1dhenVoIEFQSSBpcyBub3QgcmVhY2hhYmxlLiBQbGVhc2UgY2hlY2sgeW91ciB1cmwgYW5kIHBvcnQuJ307XG4gICAgICB9XG4gICAgICB0aHJvdyBlcnJvcjtcbiAgICB9XG4gIH1cbn0iXX0=