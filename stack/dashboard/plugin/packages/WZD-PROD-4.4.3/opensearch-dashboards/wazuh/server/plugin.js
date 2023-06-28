"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhPlugin = void 0;

var _securityFactory = require("./lib/security-factory");

var _routes = require("./routes");

var _start = require("./start");

var _cookie = require("./lib/cookie");

var ApiInterceptor = _interopRequireWildcard(require("./lib/api-interceptor"));

var _operators = require("rxjs/operators");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class WazuhPlugin {
  constructor(initializerContext) {
    this.initializerContext = initializerContext;

    _defineProperty(this, "logger", void 0);

    this.logger = initializerContext.logger.get();
  }

  async setup(core, plugins) {
    this.logger.debug('Wazuh-wui: Setup');
    const wazuhSecurity = await (0, _securityFactory.SecurityObj)(plugins);
    const serverInfo = core.http.getServerInfo();
    core.http.registerRouteHandlerContext('wazuh', (context, request) => {
      return {
        logger: this.logger,
        server: {
          info: serverInfo
        },
        plugins,
        security: wazuhSecurity,
        api: {
          client: {
            asInternalUser: {
              authenticate: async apiHostID => await ApiInterceptor.authenticate(apiHostID),
              request: async (method, path, data, options) => await ApiInterceptor.requestAsInternalUser(method, path, data, options)
            },
            asCurrentUser: {
              authenticate: async apiHostID => await ApiInterceptor.authenticate(apiHostID, (await wazuhSecurity.getCurrentUser(request, context)).authContext),
              request: async (method, path, data, options) => await ApiInterceptor.requestAsCurrentUser(method, path, data, { ...options,
                token: (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token')
              })
            }
          }
        }
      };
    }); // Add custom headers to the responses

    core.http.registerOnPreResponse((request, response, toolkit) => {
      const additionalHeaders = {
        'x-frame-options': 'sameorigin'
      };
      return toolkit.next({
        headers: additionalHeaders
      });
    }); // Routes

    const router = core.http.createRouter();
    (0, _routes.setupRoutes)(router);
    return {};
  }

  async start(core) {
    const globalConfiguration = await this.initializerContext.config.legacy.globalConfig$.pipe((0, _operators.first)()).toPromise();
    const wazuhApiClient = {
      client: {
        asInternalUser: {
          authenticate: async apiHostID => await ApiInterceptor.authenticate(apiHostID),
          request: async (method, path, data, options) => await ApiInterceptor.requestAsInternalUser(method, path, data, options)
        }
      }
    };
    const contextServer = {
      config: globalConfiguration
    }; // Initialize

    (0, _start.jobInitializeRun)({
      core,
      wazuh: {
        logger: this.logger.get('initialize'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Migration tasks

    (0, _start.jobMigrationTasksRun)({
      core,
      wazuh: {
        logger: this.logger.get('migration-task'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Monitoring

    (0, _start.jobMonitoringRun)({
      core,
      wazuh: {
        logger: this.logger.get('monitoring'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Scheduler

    (0, _start.jobSchedulerRun)({
      core,
      wazuh: {
        logger: this.logger.get('cron-scheduler'),
        api: wazuhApiClient
      },
      server: contextServer
    }); // Queue

    (0, _start.jobQueueRun)({
      core,
      wazuh: {
        logger: this.logger.get('queue'),
        api: wazuhApiClient
      },
      server: contextServer
    });
    return {};
  }

  stop() {}

}

exports.WazuhPlugin = WazuhPlugin;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInBsdWdpbi50cyJdLCJuYW1lcyI6WyJXYXp1aFBsdWdpbiIsImNvbnN0cnVjdG9yIiwiaW5pdGlhbGl6ZXJDb250ZXh0IiwibG9nZ2VyIiwiZ2V0Iiwic2V0dXAiLCJjb3JlIiwicGx1Z2lucyIsImRlYnVnIiwid2F6dWhTZWN1cml0eSIsInNlcnZlckluZm8iLCJodHRwIiwiZ2V0U2VydmVySW5mbyIsInJlZ2lzdGVyUm91dGVIYW5kbGVyQ29udGV4dCIsImNvbnRleHQiLCJyZXF1ZXN0Iiwic2VydmVyIiwiaW5mbyIsInNlY3VyaXR5IiwiYXBpIiwiY2xpZW50IiwiYXNJbnRlcm5hbFVzZXIiLCJhdXRoZW50aWNhdGUiLCJhcGlIb3N0SUQiLCJBcGlJbnRlcmNlcHRvciIsIm1ldGhvZCIsInBhdGgiLCJkYXRhIiwib3B0aW9ucyIsInJlcXVlc3RBc0ludGVybmFsVXNlciIsImFzQ3VycmVudFVzZXIiLCJnZXRDdXJyZW50VXNlciIsImF1dGhDb250ZXh0IiwicmVxdWVzdEFzQ3VycmVudFVzZXIiLCJ0b2tlbiIsImhlYWRlcnMiLCJjb29raWUiLCJyZWdpc3Rlck9uUHJlUmVzcG9uc2UiLCJyZXNwb25zZSIsInRvb2xraXQiLCJhZGRpdGlvbmFsSGVhZGVycyIsIm5leHQiLCJyb3V0ZXIiLCJjcmVhdGVSb3V0ZXIiLCJzdGFydCIsImdsb2JhbENvbmZpZ3VyYXRpb24iLCJjb25maWciLCJsZWdhY3kiLCJnbG9iYWxDb25maWckIiwicGlwZSIsInRvUHJvbWlzZSIsIndhenVoQXBpQ2xpZW50IiwiY29udGV4dFNlcnZlciIsIndhenVoIiwic3RvcCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQTZCQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFHQTs7Ozs7Ozs7QUF3Qk8sTUFBTUEsV0FBTixDQUF3RTtBQUc3RUMsRUFBQUEsV0FBVyxDQUFrQkMsa0JBQWxCLEVBQWdFO0FBQUEsU0FBOUNBLGtCQUE4QyxHQUE5Q0Esa0JBQThDOztBQUFBOztBQUN6RSxT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QUFNZm5DLE1BQUFBLE1BQU0sRUFBRW9DO0FBTk8sS0FBakIsRUFwQ2tDLENBNkNsQzs7QUFDQSxnQ0FBZ0I7QUFDZDlDLE1BQUFBLElBRGM7QUFFZCtDLE1BQUFBLEtBQUssRUFBRTtBQUNMbEQsUUFBQUEsTUFBTSxFQUFFLEtBQUtBLE1BQUwsQ0FBWUMsR0FBWixDQUFnQixnQkFBaEIsQ0FESDtBQUVMZSxRQUFBQSxHQUFHLEVBQUVnQztBQUZBLE9BRk87QUFNZG5DLE1BQUFBLE1BQU0sRUFBRW9DO0FBTk0sS0FBaEIsRUE5Q2tDLENBdURsQzs7QUFDQSw0QkFBWTtBQUNWOUMsTUFBQUEsSUFEVTtBQUVWK0MsTUFBQUEsS0FBSyxFQUFFO0FBQ0xsRCxRQUFBQSxNQUFNLEVBQUUsS0FBS0EsTUFBTCxDQUFZQyxHQUFaLENBQWdCLE9BQWhCLENBREg7QUFFTGUsUUFBQUEsR0FBRyxFQUFFZ0M7QUFGQSxPQUZHO0FBTVZuQyxNQUFBQSxNQUFNLEVBQUVvQztBQU5FLEtBQVo7QUFRQSxXQUFPLEVBQVA7QUFDRDs7QUFFTUUsRUFBQUEsSUFBSSxHQUFHLENBQUc7O0FBdEg0RCIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBMaWNlbnNlZCB0byBFbGFzdGljc2VhcmNoIEIuVi4gdW5kZXIgb25lIG9yIG1vcmUgY29udHJpYnV0b3JcbiAqIGxpY2Vuc2UgYWdyZWVtZW50cy4gU2VlIHRoZSBOT1RJQ0UgZmlsZSBkaXN0cmlidXRlZCB3aXRoXG4gKiB0aGlzIHdvcmsgZm9yIGFkZGl0aW9uYWwgaW5mb3JtYXRpb24gcmVnYXJkaW5nIGNvcHlyaWdodFxuICogb3duZXJzaGlwLiBFbGFzdGljc2VhcmNoIEIuVi4gbGljZW5zZXMgdGhpcyBmaWxlIHRvIHlvdSB1bmRlclxuICogdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTsgeW91IG1heVxuICogbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbiAqIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuICpcbiAqICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuICpcbiAqIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZyxcbiAqIHNvZnR3YXJlIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuXG4gKiBcIkFTIElTXCIgQkFTSVMsIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWVxuICogS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4gIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlXG4gKiBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kIGxpbWl0YXRpb25zXG4gKiB1bmRlciB0aGUgTGljZW5zZS5cbiAqL1xuXG5pbXBvcnQge1xuICBDb3JlU2V0dXAsXG4gIENvcmVTdGFydCxcbiAgTG9nZ2VyLFxuICBQbHVnaW4sXG4gIFBsdWdpbkluaXRpYWxpemVyQ29udGV4dCxcbiAgU2hhcmVkR2xvYmFsQ29uZmlnLFxufSBmcm9tICdvcGVuc2VhcmNoX2Rhc2hib2FyZHMvc2VydmVyJztcblxuaW1wb3J0IHsgV2F6dWhQbHVnaW5TZXR1cCwgV2F6dWhQbHVnaW5TdGFydCwgUGx1Z2luU2V0dXAgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IFNlY3VyaXR5T2JqLCBJU2VjdXJpdHlGYWN0b3J5IH0gZnJvbSAnLi9saWIvc2VjdXJpdHktZmFjdG9yeSc7XG5pbXBvcnQgeyBzZXR1cFJvdXRlcyB9IGZyb20gJy4vcm91dGVzJztcbmltcG9ydCB7IGpvYkluaXRpYWxpemVSdW4sIGpvYk1vbml0b3JpbmdSdW4sIGpvYlNjaGVkdWxlclJ1biwgam9iUXVldWVSdW4sIGpvYk1pZ3JhdGlvblRhc2tzUnVuIH0gZnJvbSAnLi9zdGFydCc7XG5pbXBvcnQgeyBnZXRDb29raWVWYWx1ZUJ5TmFtZSB9IGZyb20gJy4vbGliL2Nvb2tpZSc7XG5pbXBvcnQgKiBhcyBBcGlJbnRlcmNlcHRvciAgZnJvbSAnLi9saWIvYXBpLWludGVyY2VwdG9yJztcbmltcG9ydCB7IHNjaGVtYSwgVHlwZU9mIH0gZnJvbSAnQG9zZC9jb25maWctc2NoZW1hJztcbmltcG9ydCB0eXBlIHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0IHsgZmlyc3QgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5cbmRlY2xhcmUgbW9kdWxlICdvcGVuc2VhcmNoX2Rhc2hib2FyZHMvc2VydmVyJyB7XG4gIGludGVyZmFjZSBSZXF1ZXN0SGFuZGxlckNvbnRleHQge1xuICAgIHdhenVoOiB7XG4gICAgICBsb2dnZXI6IExvZ2dlcixcbiAgICAgIHBsdWdpbnM6IFBsdWdpblNldHVwLFxuICAgICAgc2VjdXJpdHk6IElTZWN1cml0eUZhY3RvcnlcbiAgICAgIGFwaToge1xuICAgICAgICBjbGllbnQ6IHtcbiAgICAgICAgICBhc0ludGVybmFsVXNlcjoge1xuICAgICAgICAgICAgYXV0aGVudGljYXRlOiAoYXBpSG9zdElEOiBzdHJpbmcpID0+IFByb21pc2U8c3RyaW5nPlxuICAgICAgICAgICAgcmVxdWVzdDogKG1ldGhvZDogc3RyaW5nLCBwYXRoOiBzdHJpbmcsIGRhdGE6IGFueSwgb3B0aW9uczoge2FwaUhvc3RJRDogc3RyaW5nLCBmb3JjZVJlZnJlc2g/OmJvb2xlYW59KSA9PiBQcm9taXNlPGFueT5cbiAgICAgICAgICB9LFxuICAgICAgICAgIGFzQ3VycmVudFVzZXI6IHtcbiAgICAgICAgICAgIGF1dGhlbnRpY2F0ZTogKGFwaUhvc3RJRDogc3RyaW5nKSA9PiBQcm9taXNlPHN0cmluZz5cbiAgICAgICAgICAgIHJlcXVlc3Q6IChtZXRob2Q6IHN0cmluZywgcGF0aDogc3RyaW5nLCBkYXRhOiBhbnksIG9wdGlvbnM6IHthcGlIb3N0SUQ6IHN0cmluZywgZm9yY2VSZWZyZXNoPzpib29sZWFufSkgPT4gUHJvbWlzZTxhbnk+XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgV2F6dWhQbHVnaW4gaW1wbGVtZW50cyBQbHVnaW48V2F6dWhQbHVnaW5TZXR1cCwgV2F6dWhQbHVnaW5TdGFydD4ge1xuICBwcml2YXRlIHJlYWRvbmx5IGxvZ2dlcjogTG9nZ2VyO1xuXG4gIGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgaW5pdGlhbGl6ZXJDb250ZXh0OiBQbHVnaW5Jbml0aWFsaXplckNvbnRleHQpIHtcbiAgICB0aGlzLmxvZ2dlciA9IGluaXRpYWxpemVyQ29udGV4dC5sb2dnZXIuZ2V0KCk7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgc2V0dXAoY29yZTogQ29yZVNldHVwLCBwbHVnaW5zOiBQbHVnaW5TZXR1cCkge1xuICAgIHRoaXMubG9nZ2VyLmRlYnVnKCdXYXp1aC13dWk6IFNldHVwJyk7XG5cbiAgICBjb25zdCB3YXp1aFNlY3VyaXR5ID0gYXdhaXQgU2VjdXJpdHlPYmoocGx1Z2lucyk7XG4gICAgY29uc3Qgc2VydmVySW5mbyA9IGNvcmUuaHR0cC5nZXRTZXJ2ZXJJbmZvKCk7XG5cbiAgICBjb3JlLmh0dHAucmVnaXN0ZXJSb3V0ZUhhbmRsZXJDb250ZXh0KCd3YXp1aCcsIChjb250ZXh0LCByZXF1ZXN0KSA9PiB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBsb2dnZXI6IHRoaXMubG9nZ2VyLFxuICAgICAgICBzZXJ2ZXI6IHtcbiAgICAgICAgICBpbmZvOiBzZXJ2ZXJJbmZvLFxuICAgICAgICB9LFxuICAgICAgICBwbHVnaW5zLFxuICAgICAgICBzZWN1cml0eTogd2F6dWhTZWN1cml0eSxcbiAgICAgICAgYXBpOiB7XG4gICAgICAgICAgY2xpZW50OiB7XG4gICAgICAgICAgICBhc0ludGVybmFsVXNlcjoge1xuICAgICAgICAgICAgICBhdXRoZW50aWNhdGU6IGFzeW5jIChhcGlIb3N0SUQpID0+IGF3YWl0IEFwaUludGVyY2VwdG9yLmF1dGhlbnRpY2F0ZShhcGlIb3N0SUQpLFxuICAgICAgICAgICAgICByZXF1ZXN0OiBhc3luYyAobWV0aG9kLCBwYXRoLCBkYXRhLCBvcHRpb25zKSA9PiBhd2FpdCBBcGlJbnRlcmNlcHRvci5yZXF1ZXN0QXNJbnRlcm5hbFVzZXIobWV0aG9kLCBwYXRoLCBkYXRhLCBvcHRpb25zKSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBhc0N1cnJlbnRVc2VyOiB7XG4gICAgICAgICAgICAgIGF1dGhlbnRpY2F0ZTogYXN5bmMgKGFwaUhvc3RJRCkgPT4gYXdhaXQgQXBpSW50ZXJjZXB0b3IuYXV0aGVudGljYXRlKGFwaUhvc3RJRCwgKGF3YWl0IHdhenVoU2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCkpLmF1dGhDb250ZXh0KSxcbiAgICAgICAgICAgICAgcmVxdWVzdDogYXN5bmMgKG1ldGhvZCwgcGF0aCwgZGF0YSwgb3B0aW9ucykgPT4gYXdhaXQgQXBpSW50ZXJjZXB0b3IucmVxdWVzdEFzQ3VycmVudFVzZXIobWV0aG9kLCBwYXRoLCBkYXRhLCB7Li4ub3B0aW9ucywgdG9rZW46IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei10b2tlbicpfSksXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuICAgIH0pO1xuXG4gICAgLy8gQWRkIGN1c3RvbSBoZWFkZXJzIHRvIHRoZSByZXNwb25zZXNcbiAgICBjb3JlLmh0dHAucmVnaXN0ZXJPblByZVJlc3BvbnNlKChyZXF1ZXN0LCByZXNwb25zZSwgdG9vbGtpdCkgPT4ge1xuICAgICAgY29uc3QgYWRkaXRpb25hbEhlYWRlcnMgPSB7XG4gICAgICAgICd4LWZyYW1lLW9wdGlvbnMnOiAnc2FtZW9yaWdpbicsXG4gICAgICB9O1xuICAgICAgcmV0dXJuIHRvb2xraXQubmV4dCh7IGhlYWRlcnM6IGFkZGl0aW9uYWxIZWFkZXJzIH0pO1xuICAgIH0pO1xuXG4gICAgLy8gUm91dGVzXG4gICAgY29uc3Qgcm91dGVyID0gY29yZS5odHRwLmNyZWF0ZVJvdXRlcigpO1xuICAgIHNldHVwUm91dGVzKHJvdXRlcik7XG5cbiAgICByZXR1cm4ge307XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgc3RhcnQoY29yZTogQ29yZVN0YXJ0KSB7XG4gICAgY29uc3QgZ2xvYmFsQ29uZmlndXJhdGlvbjogU2hhcmVkR2xvYmFsQ29uZmlnID0gYXdhaXQgdGhpcy5pbml0aWFsaXplckNvbnRleHQuY29uZmlnLmxlZ2FjeS5nbG9iYWxDb25maWckLnBpcGUoZmlyc3QoKSkudG9Qcm9taXNlKCk7XG4gICAgY29uc3Qgd2F6dWhBcGlDbGllbnQgPSB7XG4gICAgICBjbGllbnQ6IHtcbiAgICAgICAgYXNJbnRlcm5hbFVzZXI6IHtcbiAgICAgICAgICBhdXRoZW50aWNhdGU6IGFzeW5jIChhcGlIb3N0SUQpID0+IGF3YWl0IEFwaUludGVyY2VwdG9yLmF1dGhlbnRpY2F0ZShhcGlIb3N0SUQpLFxuICAgICAgICAgIHJlcXVlc3Q6IGFzeW5jIChtZXRob2QsIHBhdGgsIGRhdGEsIG9wdGlvbnMpID0+IGF3YWl0IEFwaUludGVyY2VwdG9yLnJlcXVlc3RBc0ludGVybmFsVXNlcihtZXRob2QsIHBhdGgsIGRhdGEsIG9wdGlvbnMpLFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfTtcblxuICAgIGNvbnN0IGNvbnRleHRTZXJ2ZXIgPSB7XG4gICAgICBjb25maWc6IGdsb2JhbENvbmZpZ3VyYXRpb25cbiAgICB9O1xuXG4gICAgLy8gSW5pdGlhbGl6ZVxuICAgIGpvYkluaXRpYWxpemVSdW4oe1xuICAgICAgY29yZSxcbiAgICAgIHdhenVoOiB7XG4gICAgICAgIGxvZ2dlcjogdGhpcy5sb2dnZXIuZ2V0KCdpbml0aWFsaXplJyksXG4gICAgICAgIGFwaTogd2F6dWhBcGlDbGllbnRcbiAgICAgIH0sXG4gICAgICBzZXJ2ZXI6IGNvbnRleHRTZXJ2ZXJcbiAgICB9KTtcblxuICAgIC8vIE1pZ3JhdGlvbiB0YXNrc1xuICAgIGpvYk1pZ3JhdGlvblRhc2tzUnVuKHtcbiAgICAgIGNvcmUsIFxuICAgICAgd2F6dWg6IHtcbiAgICAgICAgbG9nZ2VyOiB0aGlzLmxvZ2dlci5nZXQoJ21pZ3JhdGlvbi10YXNrJyksXG4gICAgICAgIGFwaTogd2F6dWhBcGlDbGllbnRcbiAgICAgIH0sXG4gICAgICBzZXJ2ZXI6IGNvbnRleHRTZXJ2ZXJcbiAgICB9KTtcblxuICAgIC8vIE1vbml0b3JpbmdcbiAgICBqb2JNb25pdG9yaW5nUnVuKHtcbiAgICAgIGNvcmUsXG4gICAgICB3YXp1aDoge1xuICAgICAgICBsb2dnZXI6IHRoaXMubG9nZ2VyLmdldCgnbW9uaXRvcmluZycpLFxuICAgICAgICBhcGk6IHdhenVoQXBpQ2xpZW50XG4gICAgICB9LFxuICAgICAgc2VydmVyOiBjb250ZXh0U2VydmVyXG4gICAgfSk7XG5cbiAgICAvLyBTY2hlZHVsZXJcbiAgICBqb2JTY2hlZHVsZXJSdW4oe1xuICAgICAgY29yZSxcbiAgICAgIHdhenVoOiB7XG4gICAgICAgIGxvZ2dlcjogdGhpcy5sb2dnZXIuZ2V0KCdjcm9uLXNjaGVkdWxlcicpLFxuICAgICAgICBhcGk6IHdhenVoQXBpQ2xpZW50XG4gICAgICB9LFxuICAgICAgc2VydmVyOiBjb250ZXh0U2VydmVyXG4gICAgfSk7XG5cbiAgICAvLyBRdWV1ZVxuICAgIGpvYlF1ZXVlUnVuKHtcbiAgICAgIGNvcmUsXG4gICAgICB3YXp1aDoge1xuICAgICAgICBsb2dnZXI6IHRoaXMubG9nZ2VyLmdldCgncXVldWUnKSxcbiAgICAgICAgYXBpOiB3YXp1aEFwaUNsaWVudFxuICAgICAgfSxcbiAgICAgIHNlcnZlcjogY29udGV4dFNlcnZlclxuICAgIH0pO1xuICAgIHJldHVybiB7fTtcbiAgfVxuXG4gIHB1YmxpYyBzdG9wKCkgeyB9XG59XG4iXX0=