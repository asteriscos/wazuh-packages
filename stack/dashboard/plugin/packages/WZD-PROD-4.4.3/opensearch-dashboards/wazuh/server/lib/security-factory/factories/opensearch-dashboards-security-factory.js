"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.OpenSearchDashboardsSecurityFactory = void 0;

var _constants = require("../../../../common/constants");

var _md = _interopRequireDefault(require("md5"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class OpenSearchDashboardsSecurityFactory {
  constructor(securityDashboards) {
    this.securityDashboards = securityDashboards;

    _defineProperty(this, "platform", _constants.WAZUH_SECURITY_PLUGIN_OPENSEARCH_DASHBOARDS_SECURITY);
  }

  async getCurrentUser(request, context) {
    try {
      const params = {
        path: `/_opendistro/_security/api/account`,
        method: 'GET'
      };
      const {
        body: authContext
      } = await context.core.opensearch.client.asCurrentUser.transport.request(params);
      const username = this.getUserName(authContext);
      return {
        username,
        authContext,
        hashUsername: (0, _md.default)(username)
      };
    } catch (error) {
      throw error;
    }
  }

  getUserName(authContext) {
    return authContext['user_name'];
  }

}

exports.OpenSearchDashboardsSecurityFactory = OpenSearchDashboardsSecurityFactory;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm9wZW5zZWFyY2gtZGFzaGJvYXJkcy1zZWN1cml0eS1mYWN0b3J5LnRzIl0sIm5hbWVzIjpbIk9wZW5TZWFyY2hEYXNoYm9hcmRzU2VjdXJpdHlGYWN0b3J5IiwiY29uc3RydWN0b3IiLCJzZWN1cml0eURhc2hib2FyZHMiLCJXQVpVSF9TRUNVUklUWV9QTFVHSU5fT1BFTlNFQVJDSF9EQVNIQk9BUkRTX1NFQ1VSSVRZIiwiZ2V0Q3VycmVudFVzZXIiLCJyZXF1ZXN0IiwiY29udGV4dCIsInBhcmFtcyIsInBhdGgiLCJtZXRob2QiLCJib2R5IiwiYXV0aENvbnRleHQiLCJjb3JlIiwib3BlbnNlYXJjaCIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJ0cmFuc3BvcnQiLCJ1c2VybmFtZSIsImdldFVzZXJOYW1lIiwiaGFzaFVzZXJuYW1lIiwiZXJyb3IiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFFQTs7QUFDQTs7Ozs7O0FBRU8sTUFBTUEsbUNBQU4sQ0FBc0U7QUFHM0VDLEVBQUFBLFdBQVcsQ0FBU0Msa0JBQVQsRUFBa0M7QUFBQSxTQUF6QkEsa0JBQXlCLEdBQXpCQSxrQkFBeUI7O0FBQUEsc0NBRjFCQywrREFFMEI7QUFDNUM7O0FBRW1CLFFBQWRDLGNBQWMsQ0FBQ0MsT0FBRCxFQUF1Q0MsT0FBdkMsRUFBc0U7QUFDeEYsUUFBSTtBQUNGLFlBQU1DLE1BQU0sR0FBRztBQUNiQyxRQUFBQSxJQUFJLEVBQUcsb0NBRE07QUFFYkMsUUFBQUEsTUFBTSxFQUFFO0FBRkssT0FBZjtBQUtBLFlBQU07QUFBQ0MsUUFBQUEsSUFBSSxFQUFFQztBQUFQLFVBQXNCLE1BQU1MLE9BQU8sQ0FBQ00sSUFBUixDQUFhQyxVQUFiLENBQXdCQyxNQUF4QixDQUErQkMsYUFBL0IsQ0FBNkNDLFNBQTdDLENBQXVEWCxPQUF2RCxDQUErREUsTUFBL0QsQ0FBbEM7QUFDQSxZQUFNVSxRQUFRLEdBQUcsS0FBS0MsV0FBTCxDQUFpQlAsV0FBakIsQ0FBakI7QUFDQSxhQUFPO0FBQUVNLFFBQUFBLFFBQUY7QUFBWU4sUUFBQUEsV0FBWjtBQUF5QlEsUUFBQUEsWUFBWSxFQUFFLGlCQUFJRixRQUFKO0FBQXZDLE9BQVA7QUFDRCxLQVRELENBU0UsT0FBT0csS0FBUCxFQUFjO0FBQ2QsWUFBTUEsS0FBTjtBQUNEO0FBQ0Y7O0FBRURGLEVBQUFBLFdBQVcsQ0FBQ1AsV0FBRCxFQUFrQjtBQUMzQixXQUFPQSxXQUFXLENBQUMsV0FBRCxDQUFsQjtBQUNEOztBQXZCMEUiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJU2VjdXJpdHlGYWN0b3J5IH0gZnJvbSAnLi4nXG5pbXBvcnQgeyBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIFJlcXVlc3RIYW5kbGVyQ29udGV4dCB9IGZyb20gJ3NyYy9jb3JlL3NlcnZlcic7XG5pbXBvcnQgeyBXQVpVSF9TRUNVUklUWV9QTFVHSU5fT1BFTlNFQVJDSF9EQVNIQk9BUkRTX1NFQ1VSSVRZIH0gZnJvbSAnLi4vLi4vLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgbWQ1IGZyb20gJ21kNSc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuU2VhcmNoRGFzaGJvYXJkc1NlY3VyaXR5RmFjdG9yeSBpbXBsZW1lbnRzIElTZWN1cml0eUZhY3Rvcnkge1xuICBwbGF0Zm9ybTogc3RyaW5nID0gV0FaVUhfU0VDVVJJVFlfUExVR0lOX09QRU5TRUFSQ0hfREFTSEJPQVJEU19TRUNVUklUWTtcblxuICBjb25zdHJ1Y3Rvcihwcml2YXRlIHNlY3VyaXR5RGFzaGJvYXJkczogYW55KSB7XG4gIH1cblxuICBhc3luYyBnZXRDdXJyZW50VXNlcihyZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIGNvbnRleHQ6UmVxdWVzdEhhbmRsZXJDb250ZXh0KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHBhcmFtcyA9IHtcbiAgICAgICAgcGF0aDogYC9fb3BlbmRpc3Ryby9fc2VjdXJpdHkvYXBpL2FjY291bnRgLFxuICAgICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgfTtcblxuICAgICAgY29uc3Qge2JvZHk6IGF1dGhDb250ZXh0fSA9IGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnRyYW5zcG9ydC5yZXF1ZXN0KHBhcmFtcyk7XG4gICAgICBjb25zdCB1c2VybmFtZSA9IHRoaXMuZ2V0VXNlck5hbWUoYXV0aENvbnRleHQpO1xuICAgICAgcmV0dXJuIHsgdXNlcm5hbWUsIGF1dGhDb250ZXh0LCBoYXNoVXNlcm5hbWU6IG1kNSh1c2VybmFtZSkgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICB9XG5cbiAgZ2V0VXNlck5hbWUoYXV0aENvbnRleHQ6YW55KSB7XG4gICAgcmV0dXJuIGF1dGhDb250ZXh0Wyd1c2VyX25hbWUnXVxuICB9XG59XG4iXX0=