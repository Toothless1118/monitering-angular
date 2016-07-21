angular.module('bl.analyze.solar.surface')
  .service('kmService', ['$window', function ($window) {
      this.trackEvent = function(type, action, contentObj) {
        $window._kmq.push([type, action, contentObj]);
      };
    }
  ]);