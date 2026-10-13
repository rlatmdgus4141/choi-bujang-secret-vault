(() => {
  const connection = document.querySelector('#connection-state');
  const button = document.querySelector('#install-app');
  const installState = document.querySelector('#install-state');
  let prompt;
  const online = () => { connection.textContent = navigator.onLine
    ? '온라인: 로그인과 서버의 기기 승인이 필요합니다.'
    : '오프라인: 보호 자료를 표시하지 않습니다. 연결 후 다시 로그인해 주세요.'; };
  window.addEventListener('online', online); window.addEventListener('offline', online); online();
  window.addEventListener('beforeinstallprompt', event => { event.preventDefault(); prompt = event; button.hidden = false; });
  button.addEventListener('click', async () => {
    if (!prompt) return;
    await prompt.prompt(); await prompt.userChoice; prompt = null; button.hidden = true;
    installState.textContent = '설치 상태와 서버 기기 승인은 별도로 확인합니다.';
  });
  window.addEventListener('appinstalled', () => {
    installState.textContent = '앱이 설치됐습니다. 서버 기기 승인은 별도로 진행하세요.'; button.hidden = true;
  });
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {
    installState.textContent = '오프라인 안내를 준비하지 못했습니다. 온라인 화면은 계속 사용할 수 있습니다.';
  });
})();
