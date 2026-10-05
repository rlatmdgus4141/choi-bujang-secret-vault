(() => {
  'use strict';
  // Project URL과 publishable key는 공개용입니다. 서버 전용 키는 사용하지 않습니다.
  const projectUrl = 'https://nsqtwulghnijprefvfud.supabase.co';
  const publishableKey = 'sb_publishable_9ohhX0Y5CQoKTfsNg7BsBQ_R0qaBGpb';
  const form = document.querySelector('#login-form');
  const email = document.querySelector('#email');
  const password = document.querySelector('#password');
  const loginButton = document.querySelector('#login-button');
  const logoutButton = document.querySelector('#logout-button');
  const state = document.querySelector('#auth-state');
  const message = document.querySelector('#auth-message');
  const section = document.querySelector('#notes-section');
  const list = document.querySelector('#notes');
  const noteForm = document.querySelector('#note-form');
  const noteTitle = document.querySelector('#note-title');
  const noteBody = document.querySelector('#note-body');
  const editorHeading = document.querySelector('#editor-heading');
  const saveNote = document.querySelector('#save-note');
  const cancelEdit = document.querySelector('#cancel-edit');
  const noteMessage = document.querySelector('#note-message');
  let client;
  let currentSession = null;
  let requestVersion = 0;
  let pendingRequest;
  let editingId = null;
  let mutationBusy = false;
  let sessionEpoch = 0;

  function resetEditor() {
    editingId = null;
    noteForm.reset();
    editorHeading.textContent = '새 메모';
    saveNote.textContent = '메모 추가';
    cancelEdit.hidden = true;
  }

  function noteError(error) {
    return ({ 400: '제목과 내용을 확인해 주세요.', 401: '로그아웃한 뒤 다시 로그인해 주세요.',
      403: '메모 소유자를 변경할 수 없습니다.',
      404: '접근할 수 있는 메모를 찾지 못했습니다.', 409: '같은 ID의 메모가 이미 있습니다.' })[error.status]
      ?? '요청 결과를 확인하지 못했습니다. 새로고침해 메모를 확인한 뒤 다시 시도해 주세요.';
  }

  async function apiRequest(session, path, { method = 'GET', body, signal } = {}) {
    const response = await fetch(path, { method, signal, cache: 'no-store',
      headers: { Authorization: `Bearer ${session.access_token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      const error = new Error('note_request_failed');
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  async function changeNote(operation) {
    if (!currentSession || mutationBusy) return;
    const session = currentSession;
    const epoch = sessionEpoch;
    mutationBusy = true;
    section.querySelectorAll('button, input, textarea').forEach(control => { control.disabled = true; });
    noteMessage.textContent = '';
    try { await operation(session, epoch); }
    catch (error) { if (epoch === sessionEpoch) noteMessage.textContent = noteError(error); }
    finally {
      mutationBusy = false;
      section.querySelectorAll('button, input, textarea').forEach(control => { control.disabled = false; });
    }
  }

  function noteRow(note) {
    const row = document.createElement('li');
    const title = document.createElement('strong');
    const content = document.createElement('span');
    title.textContent = note.title;
    content.textContent = note.body;
    const actions = document.createElement('div');
    actions.className = 'actions';
    const edit = document.createElement('button');
    edit.type = 'button'; edit.textContent = '수정';
    edit.addEventListener('click', () => changeNote(async (session, epoch) => {
      const current = await apiRequest(session, `/api/notes/${encodeURIComponent(note.id)}`);
      if (epoch !== sessionEpoch) return;
      editingId = current.id;
      noteTitle.value = current.title;
      noteBody.value = current.body;
      editorHeading.textContent = '메모 수정';
      saveNote.textContent = '수정 저장';
      cancelEdit.hidden = false;
      noteForm.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }));
    const remove = document.createElement('button');
    remove.type = 'button'; remove.className = 'secondary'; remove.textContent = '삭제';
    remove.addEventListener('click', () => {
      if (mutationBusy || !window.confirm('이 가상 메모를 삭제할까요?')) return;
      void changeNote(async (session, epoch) => {
        await apiRequest(session, `/api/notes/${encodeURIComponent(note.id)}`, { method: 'DELETE' });
        if (epoch !== sessionEpoch) return;
        if (editingId === note.id) resetEditor();
        noteMessage.textContent = '메모를 삭제했습니다.';
        await loadNotes(currentSession, ++requestVersion);
      });
    });
    actions.append(edit, remove);
    row.append(title, content, actions);
    return row;
  }

  function errorReason(error) {
    // 서버 오류 원문에 포함될 수 있는 민감한 정보 대신 알려진 원인만 표시합니다.
    if (error?.code === 'invalid_credentials') return '이메일 또는 비밀번호가 올바르지 않습니다.';
    if (error?.code === 'email_not_confirmed') return '이메일 인증이 완료되지 않았습니다. 계정의 인증 상태를 확인해 주세요.';
    if (error?.code === 'email_provider_disabled') return '이 프로젝트에서 이메일 로그인이 꺼져 있습니다.';
    if (error?.status === 429) return '요청이 많습니다. 잠시 기다린 뒤 다시 시도해 주세요.';
    if (error?.name === 'AuthRetryableFetchError' || error instanceof TypeError) {
      return '인증 서버에 연결하지 못했습니다. 인터넷 연결을 확인하고 다시 시도해 주세요.';
    }
    return '인증 요청을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.';
  }

  function setBusy(busy) {
    loginButton.disabled = busy;
    logoutButton.disabled = busy;
  }

  async function loadNotes(session, version) {
    pendingRequest?.abort();
    pendingRequest = new AbortController();
    const request = pendingRequest;
    const item = document.createElement('li');
    item.textContent = '가상 자료를 불러오는 중입니다.';
    list.replaceChildren(item);
    try {
      const data = await apiRequest(session, '/api/notes', { signal: request.signal });
      if (!Array.isArray(data)) throw new Error('invalid_notes');
      if (version !== requestVersion || !currentSession) return;
      if (!data.length) {
        item.textContent = '아직 내 메모가 없습니다. 위에서 새 메모를 추가해 주세요.';
        list.replaceChildren(item);
      } else list.replaceChildren(...data.map(noteRow));
    } catch (error) {
      if (request.signal.aborted || version !== requestVersion || !currentSession) return;
      item.textContent = error.status === 401
        ? '서버에서 로그인을 확인하지 못했습니다. 로그아웃한 뒤 다시 로그인해 주세요.'
        : '자료를 불러올 수 없습니다. 잠시 후 새로고침해 주세요.';
      list.replaceChildren(item);
    }
  }

  function renderSession(session) {
    if (currentSession?.user?.id !== session?.user?.id || !session) {
      sessionEpoch++;
      resetEditor();
      noteMessage.textContent = '';
    }
    currentSession = session;
    const version = ++requestVersion;
    pendingRequest?.abort();
    list.replaceChildren();
    form.hidden = Boolean(session);
    logoutButton.hidden = !session;
    section.hidden = !session;
    state.textContent = session ? '로그인했습니다.' : '로그인이 필요합니다.';
    password.value = '';
    if (session) void loadNotes(session, version);
  }

  cancelEdit.addEventListener('click', resetEditor);
  noteForm.addEventListener('submit', event => {
    event.preventDefault();
    if (!noteTitle.value.trim()) {
      noteMessage.textContent = '제목을 입력해 주세요.';
      return;
    }
    const id = editingId;
    const body = { title: noteTitle.value.trim(), body: noteBody.value };
    void changeNote(async (session, epoch) => {
      await apiRequest(session, id ? `/api/notes/${encodeURIComponent(id)}` : '/api/notes',
        { method: id ? 'PUT' : 'POST', body });
      if (epoch !== sessionEpoch) return;
      resetEditor();
      noteMessage.textContent = id ? '메모를 수정했습니다.' : '메모를 추가했습니다.';
      await loadNotes(currentSession, ++requestVersion);
    });
  });

  try {
    client = window.supabase.createClient(projectUrl, publishableKey, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
    });
    // 콜백 안에서 다른 Auth 메서드를 기다리지 않습니다.
    client.auth.onAuthStateChange((_event, session) => {
      message.textContent = '';
      renderSession(session);
    });
  } catch {
    state.textContent = '로그인 화면을 준비하지 못했습니다.';
    message.textContent = '페이지를 새로고침해 주세요. 문제가 계속되면 SDK 배포 상태를 확인해 주세요.';
    return;
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (loginButton.disabled) return;
    setBusy(true);
    message.textContent = '';
    try {
      const { data, error } = await client.auth.signInWithPassword({
        email: email.value.trim(), password: password.value,
      });
      if (error) message.textContent = errorReason(error);
      else if (!data.session) message.textContent = '로그인 세션을 만들지 못했습니다. 다시 시도해 주세요.';
    } catch (error) {
      message.textContent = errorReason(error);
    } finally {
      password.value = '';
      setBusy(false);
    }
  });

  logoutButton.addEventListener('click', async () => {
    if (logoutButton.disabled) return;
    setBusy(true);
    message.textContent = '';
    try {
      const { error } = await client.auth.signOut({ scope: 'local' });
      if (error) message.textContent = errorReason(error);
      else {
        renderSession(null);
        message.textContent = '로그아웃했습니다.';
        email.focus();
      }
    } catch (error) {
      message.textContent = errorReason(error);
    } finally {
      setBusy(false);
    }
  });
})();
