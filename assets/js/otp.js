(function(){
  const cfg    = (window.EOL_OTP_CFG || {});
  const grid   = document.querySelector('[data-otp-grid]');
  const form   = document.getElementById('eol-form');
  const submit = document.getElementById('eol-submit');
  const hidden = form ? form.querySelector('input[name="eol_code"]') : null;

  // --- OTP input UX ---
  if (grid) {
    const inputs = Array.from(grid.querySelectorAll('.eol-otp'));

    function updateState(){
      const val = inputs.map(i => (i.value || '').replace(/\D/g,'')).join('');
      if (hidden) hidden.value = val;
      if (submit) submit.disabled = (val.length !== inputs.length);
    }

    (inputs.find(i => !i.value) || inputs[0]).focus();

    inputs.forEach((inp, idx) => {
      inp.addEventListener('input', e => {
        e.target.value = (e.target.value || '').replace(/\D/g,'').slice(-1);
        if (e.target.value && inputs[idx+1]) inputs[idx+1].focus();
        updateState();
      });
      inp.addEventListener('keydown', e => {
        if (e.key === 'Backspace' && !inp.value && inputs[idx-1]) {
          inputs[idx-1].focus(); inputs[idx-1].value=''; updateState();
        }
        if (e.key === 'ArrowLeft' && inputs[idx-1]) inputs[idx-1].focus();
        if (e.key === 'ArrowRight' && inputs[idx+1]) inputs[idx+1].focus();
      });
      inp.addEventListener('paste', e => {
        const text = (e.clipboardData || window.clipboardData).getData('text') || '';
        const digits = text.replace(/\D/g,'').slice(0, inputs.length);
        if (!digits) return;
        e.preventDefault();
        for (let i=0;i<inputs.length;i++){ inputs[i].value = digits[i] || ''; }
        const next = inputs[Math.min(digits.length, inputs.length-1)];
        next.focus();
        updateState();
      });
    });

    if (form) form.addEventListener('submit', updateState);
  }

  // --- Resend cooldown as "Countdown (xx)" + link enable/disable ---
  const resend   = document.getElementById('eol-resend');
  const countVal = document.getElementById('eol-count');

  function setResendDisabled(state){
    if (!resend) return;
    const href = resend.getAttribute('data-href');
    if (state) {
      resend.setAttribute('aria-disabled','true');
      resend.removeAttribute('href');
    } else {
      resend.removeAttribute('aria-disabled');
      if (href) resend.setAttribute('href', href);
    }
  }

  let remaining = parseInt(cfg.remaining || 0, 10);
  if (countVal) countVal.textContent = Math.max(0, remaining);

  if (remaining > 0) {
    setResendDisabled(true);
    const iv = setInterval(() => {
      remaining -= 1;
      if (countVal) countVal.textContent = Math.max(0, remaining);
      if (remaining <= 0) {
        clearInterval(iv);
        setResendDisabled(false);
      }
    }, 1000);
  } else {
    setResendDisabled(false);
  }
})();