(function () {
  function setActiveLinks() {
    var path = window.location.pathname;
    $('.side-link, .nav-link').each(function () {
      var href = $(this).attr('href');
      if (href && href !== '/' && path.indexOf(href) === 0) {
        $(this).addClass('active');
      }
      if (href === '/' && path === '/') {
        $(this).addClass('active');
      }
    });
  }

  function enhancePredictionForm() {
    var form = $('.prediction-form');
    if (!form.length) {
      return;
    }

    form.find('input').attr({
      type: 'number',
      inputmode: 'numeric',
      autocomplete: 'off'
    });
  }

  $(function () {
    setActiveLinks();
    enhancePredictionForm();
    if (window.lucide) {
      window.lucide.createIcons();
    }
  });
})();
