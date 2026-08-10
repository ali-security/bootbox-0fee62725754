describe('bootbox sanitization', function () {
  'use strict';

  //  Anything which manages to execute flips this canary; every exploit test
  //  below asserts it is still zero once the dialog has been built.
  var originalBootbox;

  beforeEach(function () {
    originalBootbox = window.bootbox;

    //  A pristine instance, so that changes to the defaults made by a test
    //  cannot leak into the next one
    window.bootbox = bootbox.init();

    window.bootboxXssCanary = 0;

    this.create = function (options) {
      return this.dialog = bootbox.dialog($.extend({}, options, { show: false }));
    };

    this.find = function (selector) {
      return this.dialog.find(selector);
    };

    this.html = function (selector) {
      return this.find(selector).html();
    };

    this.text = function (selector) {
      return this.find(selector).text();
    };

    this.node = function (selector) {
      return this.find(selector).get(0);
    };
  });

  afterEach(function () {
    $('.bootbox').remove();
    $('.modal-backdrop').remove();
    $('body').removeClass('modal-open');

    window.bootboxXssCanary = 0;
    window.bootbox = originalBootbox;
  });


  describe('when the message contains a script tag', function () {
    beforeEach(function () {
      this.create({
        message: 'safe<script>window.bootboxXssCanary = 1;<\/script>'
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.find('.bootbox-body script').length).to.equal(0);
    });

    it('removes the contents of the script element', function () {
      expect(this.html('.bootbox-body')).not.to.contain('bootboxXssCanary');
    });

    it('keeps the surrounding text', function () {
      expect(this.text('.bootbox-body')).to.equal('safe');
    });
  });


  describe('when the message contains an "onerror" attribute', function () {
    beforeEach(function () {
      this.create({
        message: '<img src="/does-not-exist.png" alt="broken" onerror="window.bootboxXssCanary = 1;">'
      });
    });

    it('keeps the image itself', function () {
      expect(this.find('.bootbox-body img').length).to.equal(1);
    });

    it('removes the onerror attribute', function () {
      expect(this.find('.bootbox-body img').attr('onerror')).to.be.undefined;
    });

    it('does not register an error handler', function () {
      expect(this.node('.bootbox-body img').getAttribute('onerror')).to.equal(null);
      expect(this.node('.bootbox-body img').onerror).not.to.be.a('function');
    });

    it('keeps the allowed attributes', function () {
      expect(this.find('.bootbox-body img').attr('src')).to.equal('/does-not-exist.png');
      expect(this.find('.bootbox-body img').attr('alt')).to.equal('broken');
    });
  });


  describe('when the message contains an "onclick" attribute', function () {
    beforeEach(function () {
      this.create({
        message: '<div class="payload" onclick="window.bootboxXssCanary = 1;">click me</div>'
      });
    });

    it('removes the onclick attribute', function () {
      expect(this.node('.bootbox-body .payload').getAttribute('onclick')).to.equal(null);
    });

    it('does not register a click handler', function () {
      expect(this.node('.bootbox-body .payload').onclick).not.to.be.a('function');
    });

    it('does nothing when the element is clicked', function () {
      var element = this.node('.bootbox-body .payload');

      if (element.click) {
        element.click();
      }

      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('keeps the element and its text', function () {
      expect(this.text('.bootbox-body')).to.equal('click me');
    });
  });


  describe('when the message contains a "javascript:" URL', function () {
    beforeEach(function () {
      this.create({
        message: '<a href="javascript:window.bootboxXssCanary = 1;">link</a>'
      });
    });

    it('removes the href', function () {
      expect(this.find('.bootbox-body a').attr('href')).to.be.undefined;
    });

    it('keeps the link and its text', function () {
      expect(this.find('.bootbox-body a').length).to.equal(1);
      expect(this.text('.bootbox-body')).to.equal('link');
    });
  });


  describe('when the message contains an obfuscated "javascript:" URL', function () {
    beforeEach(function () {
      this.create({
        message: '<a id="mixed-case" href="JaVaScRiPt:alert(1)">a</a>' +
          '<a id="whitespace" href="java&#9;script:alert(1)">b</a>' +
          '<a id="leading-space" href=" javascript:alert(1)">c</a>' +
          '<a id="entities" href="&#106;avascript:alert(1)">d</a>'
      });
    });

    it('removes the mixed case href', function () {
      expect(this.find('#mixed-case').attr('href')).to.be.undefined;
    });

    it('removes the href containing embedded whitespace', function () {
      expect(this.find('#whitespace').attr('href')).to.be.undefined;
    });

    it('removes the href with a leading space', function () {
      expect(this.find('#leading-space').attr('href')).to.be.undefined;
    });

    it('removes the entity encoded href', function () {
      expect(this.find('#entities').attr('href')).to.be.undefined;
    });
  });


  describe('when the message contains a "data:" URL', function () {
    beforeEach(function () {
      this.create({
        message: '<a id="html-data" href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">a</a>' +
          '<img id="svg-data" src="data:image/svg+xml;base64,PHN2Zy8+">' +
          '<img id="png-data" src="data:image/png;base64,iVBORw0KGgo=">'
      });
    });

    it('removes an href pointing at a data document', function () {
      expect(this.find('#html-data').attr('href')).to.be.undefined;
    });

    it('removes an image source pointing at an SVG data URL', function () {
      expect(this.find('#svg-data').attr('src')).to.be.undefined;
    });

    it('keeps an image source pointing at a bitmap data URL', function () {
      expect(this.find('#png-data').attr('src')).to.equal('data:image/png;base64,iVBORw0KGgo=');
    });
  });


  describe('when the message contains other unsafe elements', function () {
    beforeEach(function () {
      this.create({
        message: 'before' +
          '<iframe src="javascript:window.bootboxXssCanary = 1;"></iframe>' +
          '<svg><animate onbegin="window.bootboxXssCanary = 1;" attributeName="x"></animate></svg>' +
          '<object data="payload.swf"></object>' +
          '<embed src="payload.swf">' +
          '<link rel="stylesheet" href="/evil.css">' +
          '<meta http-equiv="refresh" content="0;url=/elsewhere">' +
          '<base href="https://example.com/">' +
          '<style>body { display: none; }</style>' +
          'after'
      });
    });

    it('does not execute anything', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the iframe', function () {
      expect(this.find('.bootbox-body iframe').length).to.equal(0);
    });

    it('removes the svg and everything nested inside it', function () {
      expect(this.find('.bootbox-body svg').length).to.equal(0);
      expect(this.find('.bootbox-body animate').length).to.equal(0);
    });

    it('removes plugin, link, meta and base elements', function () {
      expect(this.find('.bootbox-body object').length).to.equal(0);
      expect(this.find('.bootbox-body embed').length).to.equal(0);
      expect(this.find('.bootbox-body link').length).to.equal(0);
      expect(this.find('.bootbox-body meta').length).to.equal(0);
      expect(this.find('.bootbox-body base').length).to.equal(0);
    });

    it('removes the style element and its contents', function () {
      expect(this.find('.bootbox-body style').length).to.equal(0);
      expect(this.html('.bootbox-body')).not.to.contain('display: none');
    });

    it('keeps the surrounding text', function () {
      expect(this.text('.bootbox-body')).to.equal('beforeafter');
    });
  });


  describe('when an unsafe element is nested inside another one', function () {
    beforeEach(function () {
      this.create({
        message: '<div><svg><style><img src="x" onerror="window.bootboxXssCanary = 1;"><\/style><\/svg><\/div>'
      });
    });

    it('does not execute anything', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the disallowed elements, along with everything nested in them', function () {
      expect(this.find('.bootbox-body svg').length).to.equal(0);
      expect(this.find('.bootbox-body style').length).to.equal(0);
      expect(this.find('.bootbox-body script').length).to.equal(0);
    });

    it('does not leave the handler behind', function () {
      expect(this.find('.bootbox-body [onerror]').length).to.equal(0);
      expect(this.html('.bootbox-body')).not.to.contain('onerror');
      expect(this.html('.bootbox-body')).not.to.contain('bootboxXssCanary');
    });
  });


  describe('when the message contains safe markup', function () {
    beforeEach(function () {
      this.create({
        message: 'hello <b>bold</b> <em>emphasis</em> <code>code</code>' +
          '<ul><li>one</li><li>two</li></ul>' +
          '<a href="https://example.com/page?a=1&amp;b=2" title="example" target="_blank" rel="noopener">link</a>' +
          '<a class="relative" href="/local/page">relative</a>' +
          '<a class="anchor" href="#somewhere">anchor</a>' +
          '<a class="mail" href="mailto:someone@example.com">mail</a>' +
          '<img src="/image.png" alt="an image" width="10" height="10">' +
          '<div class="wrapper" id="wrapper" dir="ltr" lang="en" role="note" aria-label="a note">note</div>' +
          '<table><thead><tr><th scope="col">head</th></tr></thead><tbody><tr><td colspan="2">cell</td></tr></tbody></table>'
      });
    });

    it('keeps inline formatting elements', function () {
      expect(this.find('.bootbox-body b').text()).to.equal('bold');
      expect(this.find('.bootbox-body em').text()).to.equal('emphasis');
      expect(this.find('.bootbox-body code').text()).to.equal('code');
    });

    it('keeps lists', function () {
      expect(this.find('.bootbox-body ul li').length).to.equal(2);
    });

    it('keeps absolute links, along with their allowed attributes', function () {
      var link = this.find('.bootbox-body a[target]');

      expect(link.attr('href')).to.equal('https://example.com/page?a=1&b=2');
      expect(link.attr('title')).to.equal('example');
      expect(link.attr('target')).to.equal('_blank');
      expect(link.attr('rel')).to.equal('noopener');
      expect(link.text()).to.equal('link');
    });

    it('keeps relative, anchor and mailto links', function () {
      expect(this.find('.bootbox-body a.relative').attr('href')).to.equal('/local/page');
      expect(this.find('.bootbox-body a.anchor').attr('href')).to.equal('#somewhere');
      expect(this.find('.bootbox-body a.mail').attr('href')).to.equal('mailto:someone@example.com');
    });

    it('keeps images, along with their allowed attributes', function () {
      var image = this.find('.bootbox-body img');

      expect(image.attr('src')).to.equal('/image.png');
      expect(image.attr('alt')).to.equal('an image');
      expect(image.attr('width')).to.equal('10');
      expect(image.attr('height')).to.equal('10');
    });

    it('keeps the global attributes on a container element', function () {
      var wrapper = this.find('.bootbox-body .wrapper');

      expect(wrapper.attr('id')).to.equal('wrapper');
      expect(wrapper.attr('dir')).to.equal('ltr');
      expect(wrapper.attr('lang')).to.equal('en');
      expect(wrapper.attr('role')).to.equal('note');
      expect(wrapper.attr('aria-label')).to.equal('a note');
    });

    it('keeps tabular markup', function () {
      expect(this.find('.bootbox-body table th').attr('scope')).to.equal('col');
      expect(this.find('.bootbox-body table td').attr('colspan')).to.equal('2');
    });
  });


  describe('when the message contains form markup', function () {
    beforeEach(function () {
      this.create({
        message: '<form action="/subscribe" method="post" name="signup" enctype="multipart/form-data" novalidate>' +
          '<fieldset name="details">' +
          '<legend>Your details</legend>' +
          '<label for="fullname">Name</label>' +
          '<input type="text" id="fullname" name="fullname" value="Ada" placeholder="your name" maxlength="20" size="30" required>' +
          '<input type="checkbox" name="agree" value="yes" checked>' +
          '<input type="number" name="age" min="1" max="99" step="1">' +
          '<select name="colour" size="1" required>' +
          '<optgroup label="warm"><option value="red" selected>Red</option></optgroup>' +
          '</select>' +
          '<textarea name="notes" rows="4" cols="20" placeholder="notes" maxlength="50"></textarea>' +
          '<button type="submit" name="go" value="1">Send</button>' +
          '</fieldset>' +
          '</form>'
      });
    });

    it('keeps the form, along with its allowed attributes', function () {
      var form = this.find('.bootbox-body form');

      expect(form.length).to.equal(1);
      expect(form.attr('action')).to.equal('/subscribe');
      expect(form.attr('method')).to.equal('post');
      expect(form.attr('name')).to.equal('signup');
      expect(form.attr('enctype')).to.equal('multipart/form-data');
    });

    it('keeps the fieldset, legend and label', function () {
      expect(this.find('.bootbox-body fieldset').attr('name')).to.equal('details');
      expect(this.find('.bootbox-body legend').text()).to.equal('Your details');
      expect(this.find('.bootbox-body label').attr('for')).to.equal('fullname');
    });

    it('keeps text inputs, along with their allowed attributes', function () {
      var input = this.find('.bootbox-body input[type="text"]');

      expect(input.attr('name')).to.equal('fullname');
      expect(input.attr('value')).to.equal('Ada');
      expect(input.attr('placeholder')).to.equal('your name');
      expect(input.attr('maxlength')).to.equal('20');
      expect(input.attr('size')).to.equal('30');
      expect(input.attr('required')).not.to.be.undefined;
    });

    it('keeps checkbox and number inputs, along with their allowed attributes', function () {
      expect(this.find('.bootbox-body input[type="checkbox"]').attr('checked')).not.to.be.undefined;
      expect(this.find('.bootbox-body input[type="number"]').attr('min')).to.equal('1');
      expect(this.find('.bootbox-body input[type="number"]').attr('max')).to.equal('99');
      expect(this.find('.bootbox-body input[type="number"]').attr('step')).to.equal('1');
    });

    it('keeps the select, its optgroup and its options', function () {
      expect(this.find('.bootbox-body select').attr('name')).to.equal('colour');
      expect(this.find('.bootbox-body optgroup').attr('label')).to.equal('warm');
      expect(this.find('.bootbox-body option').attr('value')).to.equal('red');
      expect(this.find('.bootbox-body option').text()).to.equal('Red');
    });

    it('keeps the textarea, along with its allowed attributes', function () {
      var textarea = this.find('.bootbox-body textarea');

      expect(textarea.attr('name')).to.equal('notes');
      expect(textarea.attr('rows')).to.equal('4');
      expect(textarea.attr('cols')).to.equal('20');
    });

    it('keeps the button, along with its allowed attributes', function () {
      var button = this.find('.bootbox-body form button');

      expect(button.attr('type')).to.equal('submit');
      expect(button.attr('name')).to.equal('go');
      expect(button.attr('value')).to.equal('1');
      expect(button.text()).to.equal('Send');
    });
  });


  describe('when the message contains table markup', function () {
    beforeEach(function () {
      this.create({
        message: '<table align="left"><caption>A caption</caption>' +
          '<colgroup span="2"></colgroup>' +
          '<thead><tr><th id="h1" scope="col" colspan="2">Head</th></tr></thead>' +
          '<tbody><tr><td colspan="2" rowspan="3" headers="h1">Cell</td></tr></tbody>' +
          '<tfoot><tr><td>Foot</td></tr></tfoot>' +
          '</table>'
      });
    });

    it('keeps the whole table structure', function () {
      expect(this.find('.bootbox-body table').length).to.equal(1);
      expect(this.find('.bootbox-body caption').text()).to.equal('A caption');
      expect(this.find('.bootbox-body colgroup').attr('span')).to.equal('2');
      expect(this.find('.bootbox-body thead tr th').length).to.equal(1);
      expect(this.find('.bootbox-body tbody tr td').length).to.equal(1);
      expect(this.find('.bootbox-body tfoot tr td').length).to.equal(1);
    });

    it('keeps the cell spanning attributes', function () {
      expect(this.find('.bootbox-body th').attr('scope')).to.equal('col');
      expect(this.find('.bootbox-body th').attr('colspan')).to.equal('2');
      expect(this.find('.bootbox-body tbody td').attr('colspan')).to.equal('2');
      expect(this.find('.bootbox-body tbody td').attr('rowspan')).to.equal('3');
      expect(this.find('.bootbox-body tbody td').attr('headers')).to.equal('h1');
    });
  });


  describe('when a form action is a "javascript:" URL', function () {
    beforeEach(function () {
      this.create({
        message: '<form action="javascript:window.bootboxXssCanary = 1;" method="post">' +
          '<input type="text" name="a">' +
          '</form>'
      });
    });

    it('removes the action', function () {
      expect(this.find('.bootbox-body form').attr('action')).to.be.undefined;
    });

    it('keeps the form and its input', function () {
      expect(this.find('.bootbox-body form').length).to.equal(1);
      expect(this.find('.bootbox-body form').attr('method')).to.equal('post');
      expect(this.find('.bootbox-body input').length).to.equal(1);
    });

    it('does not execute anything', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });
  });


  describe('when a form control carries an event handler', function () {
    beforeEach(function () {
      this.create({
        message: '<form>' +
          '<input id="field" type="text" name="a" onfocus="window.bootboxXssCanary = 1;">' +
          '<button id="go" type="button" onclick="window.bootboxXssCanary = 1;">Go</button>' +
          '<select id="choice" name="b" onchange="window.bootboxXssCanary = 1;"><option value="1">1</option></select>' +
          '<textarea id="notes" name="c" oninput="window.bootboxXssCanary = 1;"></textarea>' +
          '</form>'
      });
    });

    it('removes every handler attribute', function () {
      expect(this.find('.bootbox-body #field').attr('onfocus')).to.be.undefined;
      expect(this.find('.bootbox-body #go').attr('onclick')).to.be.undefined;
      expect(this.find('.bootbox-body #choice').attr('onchange')).to.be.undefined;
      expect(this.find('.bootbox-body #notes').attr('oninput')).to.be.undefined;
    });

    it('does not register any handler', function () {
      expect(this.node('.bootbox-body #field').onfocus).not.to.be.a('function');
      expect(this.node('.bootbox-body #go').onclick).not.to.be.a('function');
      expect(this.node('.bootbox-body #choice').onchange).not.to.be.a('function');
      expect(this.node('.bootbox-body #notes').oninput).not.to.be.a('function');
    });

    it('does nothing when the controls are used', function () {
      var button = this.node('.bootbox-body #go');
      var field = this.node('.bootbox-body #field');

      if (button.click) {
        button.click();
      }

      if (field.focus) {
        field.focus();
      }

      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('keeps the controls themselves', function () {
      expect(this.find('.bootbox-body input').attr('name')).to.equal('a');
      expect(this.find('.bootbox-body select').attr('name')).to.equal('b');
      expect(this.find('.bootbox-body textarea').attr('name')).to.equal('c');
      expect(this.find('.bootbox-body button').attr('type')).to.equal('button');
    });
  });


  describe('when a submit control carries a "formaction"', function () {
    beforeEach(function () {
      this.create({
        message: '<form action="/safe">' +
          '<button id="btn" type="submit" formaction="javascript:window.bootboxXssCanary = 1;">Go</button>' +
          '<input id="submit-input" type="submit" formaction="javascript:window.bootboxXssCanary = 1;">' +
          '</form>'
      });
    });

    it('removes formaction from the button', function () {
      expect(this.find('.bootbox-body #btn').attr('formaction')).to.be.undefined;
    });

    it('removes formaction from the submit input', function () {
      expect(this.find('.bootbox-body #submit-input').attr('formaction')).to.be.undefined;
    });

    it('leaves no "javascript:" URL anywhere in the rendered markup', function () {
      expect(this.html('.bootbox-body')).not.to.contain('javascript:');
    });

    it('keeps the safe form action', function () {
      expect(this.find('.bootbox-body form').attr('action')).to.equal('/safe');
    });
  });


  describe('when a form tries to clobber the sanitizer through a named control', function () {
    beforeEach(function () {
      this.create({
        message: '<form id="clobbered" action="javascript:window.bootboxXssCanary = 1;" onclick="window.bootboxXssCanary = 1;">' +
          '<input name="attributes">' +
          '<input name="removeAttribute">' +
          '<input name="nodeName">' +
          '</form>'
      });
    });

    it('never leaves a handler behind', function () {
      expect(this.find('.bootbox-body [onclick]').length).to.equal(0);
      expect(this.html('.bootbox-body')).not.to.contain('onclick');
    });

    it('never leaves a "javascript:" URL behind', function () {
      expect(this.find('.bootbox-body [action]').length).to.equal(0);
      expect(this.html('.bootbox-body')).not.to.contain('javascript:');
    });

    it('does not execute anything, even when the form is clicked', function () {
      var form = this.node('.bootbox-body #clobbered');

      if (form && form.click) {
        form.click();
      }

      expect(window.bootboxXssCanary).to.equal(0);
    });
  });


  describe('when the message is a plain string', function () {
    beforeEach(function () {
      this.create({
        message: 'a < b & c > d'
      });
    });

    it('renders exactly the text which was supplied', function () {
      expect(this.text('.bootbox-body')).to.equal('a < b & c > d');
    });
  });


  describe('when the message is a jQuery object', function () {
    beforeEach(function () {
      this.custom = $('<div class="custom-node"><b>hi</b></div>');

      this.create({
        message: this.custom
      });
    });

    it('inserts the node itself, untouched', function () {
      expect(this.find('.bootbox-body .custom-node').length).to.equal(1);
      expect(this.node('.bootbox-body .custom-node')).to.equal(this.custom.get(0));
    });
  });


  describe('when the message is a DOM node', function () {
    beforeEach(function () {
      this.custom = $('<div class="custom-node"></div>').get(0);

      this.create({
        message: this.custom
      });
    });

    it('inserts the node itself, untouched', function () {
      expect(this.node('.bootbox-body .custom-node')).to.equal(this.custom);
    });
  });


  describe('when the title contains unsafe markup', function () {
    beforeEach(function () {
      this.create({
        title: 'Title<script>window.bootboxXssCanary = 1;<\/script><b>!</b>',
        message: 'test'
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.find('.modal-title script').length).to.equal(0);
    });

    it('keeps the safe markup', function () {
      expect(this.find('.modal-title b').text()).to.equal('!');
      expect(this.text('.modal-title')).to.equal('Title!');
    });
  });


  describe('when a button label contains unsafe markup', function () {
    beforeEach(function () {
      this.create({
        message: 'test',
        buttons: {
          ok: {
            label: '<i class="icon" aria-hidden="true"></i> OK<script>window.bootboxXssCanary = 1;<\/script>'
          }
        }
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.find('.modal-footer button script').length).to.equal(0);
    });

    it('keeps the safe markup in the label', function () {
      expect(this.find('.modal-footer button i.icon').length).to.equal(1);
      expect($.trim(this.find('.modal-footer button').text())).to.equal('OK');
    });
  });


  describe('when an alert message contains unsafe markup', function () {
    beforeEach(function () {
      this.dialog = bootbox.alert({
        message: 'safe<script>window.bootboxXssCanary = 1;<\/script>',
        show: false
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.dialog.find('.bootbox-body script').length).to.equal(0);
    });
  });


  describe('when a confirm message contains unsafe markup', function () {
    beforeEach(function () {
      this.dialog = bootbox.confirm({
        message: 'safe<script>window.bootboxXssCanary = 1;<\/script>',
        callback: function () { },
        show: false
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.dialog.find('.bootbox-body script').length).to.equal(0);
    });
  });


  describe('when a prompt message contains unsafe markup', function () {
    beforeEach(function () {
      this.dialog = bootbox.prompt({
        title: 'What is your name?',
        message: '<b>safe</b><script>window.bootboxXssCanary = 1;<\/script>',
        callback: function () { },
        show: false
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.dialog.find('.bootbox-prompt-message script').length).to.equal(0);
    });

    it('keeps the safe markup', function () {
      expect(this.dialog.find('.bootbox-prompt-message b').text()).to.equal('safe');
    });

    it('still builds the prompt form and its input', function () {
      expect(this.dialog.find('form.bootbox-form').length).to.equal(1);
      expect(this.dialog.find('input.bootbox-input-text').length).to.equal(1);
    });
  });


  describe('when a prompt checkbox option text contains unsafe markup', function () {
    beforeEach(function () {
      this.dialog = bootbox.prompt({
        title: 'Pick one',
        inputType: 'checkbox',
        inputOptions: [
          {
            value: '1',
            text: '<b>one</b><script>window.bootboxXssCanary = 1;<\/script>'
          }
        ],
        callback: function () { },
        show: false
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.dialog.find('.bootbox-checkbox-list script').length).to.equal(0);
    });

    it('keeps the safe markup, and the checkbox itself', function () {
      expect(this.dialog.find('.bootbox-checkbox-list b').text()).to.equal('one');
      expect(this.dialog.find('.bootbox-checkbox-list input[type="checkbox"]').val()).to.equal('1');
    });
  });


  describe('when a prompt radio option text contains unsafe markup', function () {
    beforeEach(function () {
      this.dialog = bootbox.prompt({
        title: 'Pick one',
        inputType: 'radio',
        inputOptions: [
          {
            value: '1',
            text: '<b>one</b><script>window.bootboxXssCanary = 1;<\/script>'
          }
        ],
        callback: function () { },
        show: false
      });
    });

    it('does not execute the script', function () {
      expect(window.bootboxXssCanary).to.equal(0);
    });

    it('removes the script element', function () {
      expect(this.dialog.find('.bootbox-radiobutton-list script').length).to.equal(0);
    });

    it('keeps the safe markup, and the radio button itself', function () {
      expect(this.dialog.find('.bootbox-radiobutton-list b').text()).to.equal('one');
      expect(this.dialog.find('.bootbox-radiobutton-list input[type="radio"]').val()).to.equal('1');
    });
  });


  describe('when sanitization is disabled for a single dialog', function () {
    beforeEach(function () {
      this.create({
        message: '<div class="payload" onclick="window.bootboxXssCanary = 1;">raw</div>',
        sanitize: false
      });
    });

    it('leaves the markup exactly as it was supplied', function () {
      expect(this.node('.bootbox-body .payload').getAttribute('onclick')).to.equal('window.bootboxXssCanary = 1;');
    });
  });


  describe('when sanitization is disabled through the defaults', function () {
    beforeEach(function () {
      bootbox.setDefaults({ sanitize: false });

      this.create({
        message: '<div class="payload" onclick="window.bootboxXssCanary = 1;">raw</div>'
      });
    });

    it('leaves the markup exactly as it was supplied', function () {
      expect(this.node('.bootbox-body .payload').getAttribute('onclick')).to.equal('window.bootboxXssCanary = 1;');
    });

    it('can be turned back on for a single dialog', function () {
      this.create({
        message: '<div class="payload" onclick="window.bootboxXssCanary = 1;">raw</div>',
        sanitize: true
      });

      expect(this.node('.bootbox-body .payload').getAttribute('onclick')).to.equal(null);
    });
  });


  describe('when sanitization is enabled', function () {
    it('is the default', function () {
      this.create({
        message: '<div class="payload" onclick="window.bootboxXssCanary = 1;">raw</div>'
      });

      expect(this.node('.bootbox-body .payload').getAttribute('onclick')).to.equal(null);
    });
  });
});
