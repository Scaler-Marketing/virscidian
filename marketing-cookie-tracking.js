// Query-param-to-cookie tracker for Webflow pages.
//
// This script is intentionally config-driven so future cookie mappings can be
// added without touching the core logic below.
//
// How it works:
// 1. Reads selected query parameters from the current URL.
// 2. Stores them as a JSON object inside a cookie.
// 3. Merges new values with any existing cookie data by default.
//
// To add another tracked cookie later, copy the object inside CONFIG.cookies
// and change:
// - cookieName
// - queryParams
// - maxAgeSeconds
// - other cookie settings if needed
(function () {
  var CONFIG = {
    cookies: [
      {
        // Cookie that will hold marketing attribution data.
        cookieName: "marketing_tracking",
        queryParams: ["utm_medium", "utm_source", "utm_campaign", "gclid"],
        maxAgeSeconds: 60 * 60 * 24 * 90, // 90 days
        path: "/",
        sameSite: "Lax",
        mergeWithExisting: true,
        secureOnHttps: true,
      },

      // Example future config:
      // {
      //   cookieName: "additional_tracking",
      //   queryParams: ["fbclid", "msclkid"],
      //   maxAgeSeconds: 60 * 60 * 24 * 30,
      //   path: "/",
      //   sameSite: "Lax",
      //   mergeWithExisting: true,
      //   secureOnHttps: true,
      // },
    ],
  };

  function getCookie(name) {
    var namePrefix = name + "=";
    var cookies = document.cookie ? document.cookie.split("; ") : [];

    for (var i = 0; i < cookies.length; i += 1) {
      if (cookies[i].indexOf(namePrefix) === 0) {
        return cookies[i].slice(namePrefix.length);
      }
    }

    return null;
  }

  function readJsonCookie(cookieName) {
    var rawValue = getCookie(cookieName);

    if (!rawValue) {
      return {};
    }

    try {
      return JSON.parse(decodeURIComponent(rawValue));
    } catch (error) {
      return {};
    }
  }

  function writeJsonCookie(cookieConfig, value) {
    var cookieParts = [
      cookieConfig.cookieName +
        "=" +
        encodeURIComponent(JSON.stringify(value)),
      "path=" + cookieConfig.path,
      "max-age=" + cookieConfig.maxAgeSeconds,
      "SameSite=" + cookieConfig.sameSite,
    ];

    if (cookieConfig.secureOnHttps && window.location.protocol === "https:") {
      cookieParts.push("Secure");
    }

    document.cookie = cookieParts.join("; ");
  }

  function getValuesFromUrl(queryParams) {
    var searchParams = new URLSearchParams(window.location.search);
    var matchedValues = {};

    for (var i = 0; i < queryParams.length; i += 1) {
      var key = queryParams[i];
      var value = searchParams.get(key);

      if (value) {
        matchedValues[key] = value;
      }
    }

    return matchedValues;
  }

  function isEmptyObject(value) {
    return Object.keys(value).length === 0;
  }

  function processCookieConfig(cookieConfig) {
    var incomingValues = getValuesFromUrl(cookieConfig.queryParams);

    // Do nothing unless the current page actually contains relevant params.
    if (isEmptyObject(incomingValues)) {
      return;
    }

    var cookieValue = incomingValues;

    if (cookieConfig.mergeWithExisting) {
      cookieValue = Object.assign(
        {},
        readJsonCookie(cookieConfig.cookieName),
        incomingValues,
      );
    }

    writeJsonCookie(cookieConfig, cookieValue);
  }

  for (var i = 0; i < CONFIG.cookies.length; i += 1) {
    processCookieConfig(CONFIG.cookies[i]);
  }
})();
