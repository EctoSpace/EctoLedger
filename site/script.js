/**
 * Section entrance animations - adds in-view class when sections enter viewport
 */
(function () {
  var sections = document.querySelectorAll('.section-animate');
  if (!sections.length) return;

  var observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
        }
      });
    },
    { rootMargin: '0px 0px -80px 0px', threshold: 0 }
  );

  sections.forEach(function (el) {
    observer.observe(el);
  });
})();

/**
 * GitHub popup - open GitHub/Docs links in a popup window
 */
(function () {
  var GITHUB_POPUP_WIDTH = 1100;
  var GITHUB_POPUP_HEIGHT = 750;

  function openGitHubPopup(e) {
    var link = e.currentTarget;
    if (!link || !link.href) return;
    e.preventDefault();
    var left = Math.round((window.screen.width - GITHUB_POPUP_WIDTH) / 2);
    var top = Math.round((window.screen.height - GITHUB_POPUP_HEIGHT) / 2);
    var features = 'width=' + GITHUB_POPUP_WIDTH + ',height=' + GITHUB_POPUP_HEIGHT +
      ',left=' + left + ',top=' + top + ',scrollbars=yes,resizable=yes';
    window.open(link.href, 'github-ectoledger', features);
  }

  document.querySelectorAll('[data-github-popup]').forEach(function (el) {
    el.addEventListener('click', openGitHubPopup);
  });
})();
