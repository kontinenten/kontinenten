/* Kontinenten editorial dashboard - public site and email/password authenticated editor */
(() => {
  'use strict';
  const config = window.KONTINENTEN_AZURE || {};
  const configured = Boolean(config.apiBase && !config.apiBase.includes('REPLACE') && /^https:\/\//.test(config.apiBase));
  const $ = id => document.getElementById(id);
  const main = $('main-content');
  const workspace = $('editor-workspace');
  const login = $('editor-login');
  const setup = $('editor-setup');
  const panel = $('editor-edit-panel');
  const form = $('editor-article-form');
  let sessionToken = sessionStorage.getItem('kontinenten_editor_session'), account = null, me = null, articles = [], editingId = null, editingVersion = null, currentFilter = 'all';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const msg = (id, text) => { if ($(id)) $(id).textContent = text; };
  const isManager = () => ['editor','admin'].includes(me?.role);
  const fmt = value => String(value || '').split(/\n\s*\n/).filter(Boolean).map(paragraph => {
    let p = esc(paragraph.trim());
    if (p.startsWith('## ')) return `<h3>${p.slice(3)}</h3>`;
    p = p.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>').replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
    return `<p>${p.replace(/\n/g, '<br>')}</p>`;
  }).join('');
  const settingUp = () => {
    if (setup) setup.hidden = false;
    if (login) login.hidden = true;
    if (workspace) workspace.hidden = true;
  };
  function showLogin() { setup.hidden = true; login.hidden = false; workspace.hidden = true; }
  async function publicGet(path) {
    const response = await fetch(`${config.apiBase}${path}`, {cache:'no-store'});
    if (!response.ok) throw new Error(`Public stories unavailable (${response.status})`);
    return response.json();
  }
  async function authToken() {
    if (!sessionToken) throw new Error('Please sign in first');
    return sessionToken;
  }
  function clearSession() {
    sessionToken = null; sessionStorage.removeItem('kontinenten_editor_session');
    me = null; account = null; articles = [];
  }
  async function api(path, method = 'GET', value) {
    const response = await fetch(`${config.apiBase}${path}`, {
      method, headers: {'Authorization':`Bearer ${await authToken()}`, ...(value ? {'Content-Type':'application/json'} : {})},
      ...(value ? {body:JSON.stringify(value)} : {})
    });
    let data;
    try { data = await response.json(); } catch (_) { data = {}; }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }
  function closeEditing() { panel.hidden = true; $('editor-preview').hidden = true; editingId = null; editingVersion = null; }
  function editorFormData() {
    if (!form.reportValidity()) return null;
    const f = new FormData(form);
    return {title:String(f.get('title') || '').trim(), category:f.get('category'),
      author_name:String(f.get('author_name') || '').trim(), summary:String(f.get('summary') || '').trim(),
      body:String(f.get('body') || '').trim(), featured:f.get('featured') === 'true', ...(editingId ? {expected_version:editingVersion} : {})};
  }
  function putForm(article = {}) {
    editingId = article.id || null; editingVersion = article.version ?? null;
    for (const key of ['title','category','author_name','summary','body']) form.elements[key].value = article[key] || (key === 'category' ? 'opinion' : '');
    form.elements.featured.value = article.featured ? 'true' : 'false';
    if (!article.id && me) form.elements.author_name.value = me.name || '';
    $('editor-form-heading').textContent = article.id ? 'Edit article' : 'New article';
    $('editor-publish').hidden = !isManager();
    $('editor-unpublish').hidden = !isManager() || article.status !== 'published';
    panel.hidden = false;
    $('editor-preview').hidden = true;
    msg('editor-save-message', '');
    panel.scrollIntoView({behavior:'smooth',block:'start'});
  }
  function listRow(article) {
    const date = article.updated_at ? new Date(article.updated_at).toLocaleDateString() : '—';
    return `<tr><td><strong>${esc(article.title)}</strong></td><td>${esc(article.author_name)}</td><td>${esc(article.category)}</td><td><span class="editor-badge" data-status="${esc(article.status)}">${esc(article.status)}</span></td><td>${esc(date)}</td><td><button type="button" class="editor-row-button" data-edit-id="${esc(article.id)}">Edit</button></td></tr>`;
  }
  function renderWorkspace() {
    const filtered = currentFilter === 'all' ? articles : articles.filter(a => a.status === currentFilter);
    $('editor-rows').innerHTML = filtered.length ? filtered.map(listRow).join('') : '<tr><td colspan="6">No articles in this category yet.</td></tr>';
    for (const status of ['draft','review','published']) msg(`stat-${status}`, articles.filter(a => a.status === status).length);
    msg('stat-all', articles.length);
    msg('editor-identity', `${me.name} · ${me.role}`);
    workspace.hidden = false; login.hidden = true; setup.hidden = true;
    $('editor-change-panel').hidden = true;
    $('editor-add-user').hidden = me.role !== 'admin';
  }
  async function refresh() {
    const result = await api('/editor/articles');
    articles = result.articles || [];
    renderWorkspace();
  }
  async function save(status) {
    const data = editorFormData(); if (!data) return;
    msg('editor-save-message', 'Saving…');
    try {
      const result = await api(editingId ? `/editor/articles/${editingId}` : '/editor/articles', editingId ? 'PUT' : 'POST', data);
      editingId = result.article.id; editingVersion = result.article.version;
      if (status && status !== result.article.status) {
        const changed = await api(`/editor/articles/${editingId}/status`, 'POST', {status, expected_version:editingVersion});
        editingVersion = changed.article.version;
      }
      await refresh();
      const label = status === 'published' ? 'Published successfully.' : status === 'review' ? 'Submitted for review.' : 'Saved successfully.';
      msg('editor-save-message', label);
      $('editor-unpublish').hidden = !isManager() || status !== 'published';
      await loadPublic();
    } catch (error) { msg('editor-save-message', error.message); }
  }
  async function unpublish() {
    if (!editingId || !isManager()) return;
    if (!confirm('Remove this article from the public website?')) return;
    try {
      const result = await api(`/editor/articles/${editingId}/status`, 'POST', {status:'draft', expected_version:editingVersion}); editingVersion = result.article.version;
      await refresh(); await loadPublic();
      msg('editor-save-message', 'Unpublished; the draft is now private.');
      $('editor-unpublish').hidden = true;
    } catch (e) { msg('editor-save-message', e.message); }
  }
  function showPreview() {
    const f = new FormData(form), preview = $('editor-preview');
    $('editor-preview-title').textContent = String(f.get('title') || 'Untitled');
    $('editor-preview-summary').textContent = String(f.get('summary') || '');
    $('editor-preview-body').innerHTML = fmt(f.get('body'));
    preview.hidden = !preview.hidden;
    if (!preview.hidden) preview.scrollIntoView({behavior:'smooth',block:'start'});
  }
  function publicArticleItem(article) {
    const node = document.createElement('article'); node.className = 'entry';
    node.innerHTML = `<div><span class="eyebrow">${esc(article.category)}</span></div><div><h3>${esc(article.title)}</h3><p>${esc(article.summary)}</p><div class="metadata">${esc(article.author_name)}</div><button class="read-link" type="button" data-dynamic-story="${esc(article.id)}">Read the article →</button></div>`;
    return node;
  }
  let publicArticles = [], dynamicView = null;
  function showStory(id, changeHash = true) {
    const article = publicArticles.find(a => a.id === id); if (!article) return;
    document.querySelectorAll('.page.active,.article-view.active').forEach(n => n.classList.remove('active'));
    if (dynamicView) dynamicView.remove();
    dynamicView = document.createElement('section'); dynamicView.className = 'article-view active';
    dynamicView.innerHTML = `<button class="back" type="button" data-return-category="${esc(article.category)}">← Back to ${esc(article.category)}</button><header class="article-header"><span class="eyebrow">${esc(article.category)}</span><h2>${esc(article.title)}</h2><p class="lede">${esc(article.summary)}</p><p class="metadata">${esc(article.author_name)}</p></header><div class="article-body">${fmt(article.body)}</div>`;
    main.append(dynamicView);
    if (changeHash) history.replaceState(null,'',`#story-${id}`);
    window.scrollTo({top:0,behavior:'instant'});
  }
  function clearDynamic() { if (dynamicView) {dynamicView.remove(); dynamicView=null;} }
  async function loadPublic() {
    if (!configured) return;
    try {
      const result = await publicGet('/articles');
      publicArticles = result.articles || [];
      for (const category of ['opinion','report','interview']) {
        const parent = $({opinion:'opinions',report:'reports',interview:'interviews'}[category]);
        const existing = parent.querySelector('.azure-stories'); if (existing) existing.remove();
        const entries = publicArticles.filter(a => a.category === category);
        if (!entries.length) continue;
        const group = document.createElement('div'); group.className='azure-stories';
        entries.forEach(article => group.append(publicArticleItem(article)));
        parent.append(group);
      }
      const home = $('azure-home-stories');
      if (home) {
        home.replaceChildren();
        const featured = publicArticles.filter(a => a.featured).slice(0,3);
        if (featured.length) {
          const heading = document.createElement('div'); heading.className='section-heading'; heading.innerHTML='<h2>More from Kontinenten</h2>';
          const grid = document.createElement('div'); grid.className='two-cards';
          featured.forEach(a => { const card=document.createElement('article'); card.className='slot'; card.innerHTML=`<span class="eyebrow">${esc(a.category)}</span><h3>${esc(a.title)}</h3><p>${esc(a.summary)}</p><button class="read-link" type="button" data-dynamic-story="${esc(a.id)}">Read article →</button>`; grid.append(card); });
          home.append(heading,grid);
        }
      }
      const hash = location.hash.slice(1);
      if (hash.startsWith('story-')) showStory(hash.slice(6), false);
    } catch (err) { console.warn('Azure public stories:',err.message); }
  }
  async function init() {
    if (!configured) { settingUp(); return; }
    if (!sessionToken) {showLogin(); return;}
    try {
      me=(await api('/editor/me')).user;
      if (me.must_change_password) {showPasswordChange(); return;}
      await refresh();
    } catch (_) {clearSession(); showLogin();}
  }
  function showPasswordChange() {
    setup.hidden=true; login.hidden=true; workspace.hidden=true;
    $('editor-change-panel').hidden=false;
  }
  $('editor-login-form')?.addEventListener('submit', async e => {
    e.preventDefault(); msg('editor-login-message','Signing in…');
    const f=new FormData(e.currentTarget);
    try {
      const response=await fetch(`${config.apiBase}/editor/login`, {
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({email:String(f.get('email')||''),password:String(f.get('password')||'')})
      });
      const data=await response.json();
      if (!response.ok) throw new Error(data.error || `Login failed (${response.status})`);
      sessionToken=data.token; sessionStorage.setItem('kontinenten_editor_session',sessionToken);
      me=data.user; account=me; e.currentTarget.reset();
      msg('editor-login-message','');
      if (me.must_change_password) showPasswordChange(); else await refresh();
    } catch (error) { msg('editor-login-message',error.message); }
  });
  $('editor-password-form')?.addEventListener('submit',async e=>{
    e.preventDefault(); msg('editor-password-message','Updating password…');
    const f=new FormData(e.currentTarget);
    if (f.get('new_password')!==f.get('confirm_password')) {msg('editor-password-message','New passwords do not match');return;}
    try {
      await api('/editor/change-password','POST',{old_password:f.get('old_password'),new_password:f.get('new_password')});
      clearSession(); e.currentTarget.reset(); $('editor-change-panel').hidden=true;
      showLogin(); msg('editor-login-message','Password changed. Sign in using your new password.');
    } catch(error){msg('editor-password-message',error.message);}
  });
  $('editor-open-password')?.addEventListener('click',showPasswordChange);
  $('editor-cancel-password')?.addEventListener('click',()=>{
    $('editor-change-panel').hidden=true;
    if (me?.must_change_password) {clearSession();showLogin();}
    else if(me) renderWorkspace(); else showLogin();
  });
  $('editor-add-user')?.addEventListener('click',()=>{$('editor-new-user-panel').hidden=false;});
  $('editor-cancel-user')?.addEventListener('click',()=>{$('editor-new-user-panel').hidden=true;});
  $('editor-user-form')?.addEventListener('submit',async e=>{
    e.preventDefault(); msg('editor-user-message','Creating account…');
    const f=new FormData(e.currentTarget);
    try {
      await api('/editor/users','POST',{name:f.get('name'),email:f.get('email'),role:f.get('role'),password:f.get('password')});
      e.currentTarget.reset(); msg('editor-user-message','Account created. Give the temporary password privately to the editor.');
    } catch(error){msg('editor-user-message',error.message);}
  });
  $('editor-logout')?.addEventListener('click', async () => {
    try {await api('/editor/logout','POST');} catch(_){}
    clearSession();closeEditing();$('editor-change-panel').hidden=true;
    $('editor-new-user-panel').hidden=true;showLogin();
  });
  $('editor-refresh')?.addEventListener('click', () => refresh().catch(e=>msg('editor-message',e.message)));
  document.querySelectorAll('.editor-stat').forEach(btn => btn.addEventListener('click', () => { currentFilter=btn.dataset.filter; renderWorkspace(); }));
  $('editor-new')?.addEventListener('click',()=>putForm());
  $('editor-cancel')?.addEventListener('click',closeEditing);
  $('editor-save-draft')?.addEventListener('click',()=>save('draft'));
  $('editor-send-review')?.addEventListener('click',()=>save('review'));
  $('editor-publish')?.addEventListener('click',()=>save('published'));
  $('editor-unpublish')?.addEventListener('click',unpublish);
  $('editor-preview-toggle')?.addEventListener('click',showPreview);
  $('editor-rows')?.addEventListener('click',e=>{const id=e.target.closest('[data-edit-id]')?.dataset.editId;
    if (id) { const a=articles.find(x=>x.id===id); if(a) putForm(a); }});
  document.addEventListener('click',e=>{
    const story=e.target.closest('[data-dynamic-story]');
    if (story) showStory(story.dataset.dynamicStory);
    const back=e.target.closest('[data-return-category]');
    if (back) {const cat={opinion:'opinions',report:'reports',interview:'interviews'}[back.dataset.returnCategory] || 'home';clearDynamic();navigate(cat);}
    if (e.target.closest('.nav-btn,.mobile-menu-toggle,[data-article],#open-editor')) clearDynamic();
  });
  window.addEventListener('hashchange',()=> {const hash=location.hash.slice(1); if(hash.startsWith('story-'))showStory(hash.slice(6),false);else clearDynamic();});
  loadPublic(); init();
})();
