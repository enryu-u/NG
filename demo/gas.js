/* ===== Auth.gs ===== */
/** ===================== LOGIN, SESSÃO E SEGURANÇA =====================
 * Mesmo modelo do CRAS:
 * - senha guardada só como hash com sal (ninguém vê a senha na planilha);
 * - sessão no cache do servidor (6 h no máximo, 2 h parado);
 * - bloqueio depois de 5 tentativas erradas;
 * - funções de manutenção só rodam pelo editor (soDono_).
 * O navegador só consegue chamar: login, logout e chamarApi.
 */
const USU = ['login', 'nome', 'email', 'perfil', 'modulos_extras', 'tecnico', 'funcionario',
  'salt', 'hash', 'ativo', 'trocar_senha', 'criado_em', 'ultimo_acesso'];

function hashSenha_(senha, salt) {
  let h = salt + senha;
  for (let i = 0; i < CFG.LOGIN.ITERACOES; i++) {
    h = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h + salt, Utilities.Charset.UTF_8)
      .map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
  }
  return h;
}
function novoSal_() { return Utilities.getUuid().replace(/-/g, '').slice(0, 16); }

function abaUsuarios_() { return planilha_('SISTEMA').getSheetByName('USUARIOS'); }

/** Lê todos os usuários como objetos { login, nome, ..., _linha } */
function lerUsuarios_() {
  const v = abaUsuarios_().getDataRange().getValues();
  const cab = v[0].map(String);
  return v.slice(1).map((r, i) => {
    const o = { _linha: i + 2 };
    USU.forEach(k => { const j = cab.indexOf(k); o[k] = j >= 0 ? r[j] : ''; });
    return o;
  }).filter(u => String(u.login).trim());
}
function gravarUsuario_(u) {
  const aba = abaUsuarios_();
  const cab = aba.getRange(1, 1, 1, aba.getLastColumn()).getValues()[0].map(String);
  const linha = u._linha || (aba.getLastRow() + 1);
  const atual = u._linha ? aba.getRange(linha, 1, 1, cab.length).getValues()[0] : cab.map(() => '');
  USU.forEach(k => { const j = cab.indexOf(k); if (j >= 0 && u[k] !== undefined) atual[j] = u[k]; });
  aba.getRange(linha, 1, 1, cab.length).setValues([atual]);
  return linha;
}
function ativo_(u) { const a = String(u.ativo).toUpperCase(); return !(u.ativo === false || a === 'FALSE' || a === 'NÃO' || a === 'NAO'); }

/** ---------- LOGIN (público) ---------- */
function login(usuario, senha) {
  const cache = CacheService.getScriptCache();
  const alvo = normalizar_(usuario).replace(/\s/g, '');
  const chave = 'TENT_' + alvo;
  try {
    if (!alvo || !senha) return { ok: false, erro: 'Informe usuário e senha.' };
    if (Number(cache.get(chave) || 0) >= CFG.LOGIN.MAX_TENTATIVAS)
      return { ok: false, erro: 'Muitas tentativas. Aguarde 10 minutos e tente de novo.' };
    const u = lerUsuarios_().find(x => normalizar_(x.login).replace(/\s/g, '') === alvo && ativo_(x));
    senha = String(senha).trim();
    if (!u || hashSenha_(senha, String(u.salt).trim()) !== String(u.hash).trim()) {
      cache.put(chave, String(Number(cache.get(chave) || 0) + 1), CFG.LOGIN.BLOQUEIO_SEG);
      log_('LOGIN_FALHOU', alvo, '');
      return { ok: false, erro: 'Usuário ou senha incorretos.' };
    }
    cache.remove(chave);
    const token = Utilities.getUuid() + Utilities.getUuid();
    const sess = { login: String(u.login), ultimo: Date.now(), inicio: Date.now() };
    cache.put('S_' + token, JSON.stringify(sess), CFG.SESSAO.MAX_SEG);
    u.ultimo_acesso = new Date(); gravarUsuario_(u);
    log_('LOGIN', u.login, '');
    const troca = String(u.trocar_senha).toUpperCase() === 'TRUE' || u.trocar_senha === true;
    let ctx = null;
    if (!troca) { try { u.modulos = modulosDoUsuario_(u); u._sessao = sess; ctx = contexto_(u); } catch (e) { } }
    return { ok: true, token: token, trocarSenha: troca, ctx: ctx };
  } catch (e) {
    log_('ERRO', 'login', String(e && e.stack || e));
    return { ok: false, erro: 'Não foi possível entrar agora. Tente novamente.' };
  }
}

function logout(token) { try { CacheService.getScriptCache().remove('S_' + token); } catch (e) { } return true; }

/** Confere a sessão e devolve o usuário completo com a lista de módulos liberados. */
function validarSessao_(token) {
  const cache = CacheService.getScriptCache();
  const bruto = token && cache.get('S_' + token);
  const falha = () => { const e = erroUsuario_('Sua sessão terminou. Entre novamente.'); e.sessao = true; return e; };
  if (!bruto) throw falha();
  const s = JSON.parse(bruto);
  if (Date.now() - s.ultimo > CFG.SESSAO.OCIOSA_MIN * 60000 || Date.now() - (s.inicio || 0) > CFG.SESSAO.MAX_SEG * 1000) { cache.remove('S_' + token); throw falha(); }
  const u = lerUsuarios_().find(x => String(x.login) === s.login && ativo_(x));
  if (!u) { cache.remove('S_' + token); throw falha(); }
  s.ultimo = Date.now();
  cache.put('S_' + token, JSON.stringify(s), Math.max(60, Math.round(CFG.SESSAO.MAX_SEG - (Date.now() - s.inicio) / 1000)));
  u.modulos = modulosDoUsuario_(u);
  u._sessao = s;
  return u;
}

/** Módulos = módulos do perfil + extras do usuário. '*' libera tudo. */
function modulosDoUsuario_(u) {
  const perfis = lerPerfis_();
  const p = perfis.find(x => normalizar_(x.perfil) === normalizar_(u.perfil));
  const lista = (p ? p.modulos.slice() : []).concat(String(u.modulos_extras || '').split(',').map(s => s.trim()).filter(Boolean))
    .map(m => MODULOS_ANTIGOS[m] || m);
  if (lista.indexOf('*') >= 0) return Object.keys(MODULOS);
  return Object.keys(MODULOS).filter(m => lista.indexOf(m) >= 0);
}
let _perfis = null;
function lerPerfis_() {
  const v = _perfis || (_perfis = planilha_('SISTEMA').getSheetByName('PERFIS').getDataRange().getValues());
  return v.slice(1).filter(r => String(r[0]).trim()).map((r, i) => ({
    perfil: String(r[0]).trim(), descricao: String(r[1] || ''), _linha: i + 2,
    modulos: String(r[2] || '').split(',').map(s => s.trim()).filter(Boolean)
  }));
}

/** Troca da própria senha (exige a atual). */
function trocarSenha_(u, d) {
  if (String(d.nova || '').trim().length < CFG.LOGIN.SENHA_MIN) throw erroUsuario_('A senha nova precisa ter pelo menos ' + CFG.LOGIN.SENHA_MIN + ' caracteres.');
  if (hashSenha_(String(d.atual || '').trim(), String(u.salt)) !== String(u.hash)) throw erroUsuario_('A senha atual não confere.');
  u.salt = novoSal_(); u.hash = hashSenha_(String(d.nova).trim(), u.salt); u.trocar_senha = false;
  gravarUsuario_(u); log_('SENHA_TROCADA', u.login, '');
  return true;
}

/** ---------- LOG ---------- */
function log_(tipo, usuario, detalhe) {
  try {
    planilha_('SISTEMA').getSheetByName('LOG').appendRow([new Date(), tipo, String(usuario || ''), String(detalhe || '').slice(0, 1000)]);
  } catch (e) { console.error(e); }
}

/** ---------- TRAVA DAS FUNÇÕES DE EDITOR ---------- */
function soDono_() {
  let ef = '', at = '';
  try { ef = Session.getEffectiveUser().getEmail(); at = Session.getActiveUser().getEmail(); } catch (x) { }
  if (ef && at && ef === at) return;
  log_('BLOQUEADO', at || 'anônimo', 'função de editor chamada pelo navegador');
  throw new Error('Função restrita: rode pelo editor do Apps Script.');
}

/** ===== RODE NO EDITOR (uma vez) =====
 * Confere as planilhas e pastas (cria as que não abrirem, veja Instalacao.gs), cria as abas que faltarem e o primeiro administrador.
 * A senha temporária aparece no "Registro de execução". No primeiro acesso o sistema pede para trocar.
 */
function configuracaoInicial() {
  soDono_();
  instalarPlanilhas_();
  const ss = planilha_('SISTEMA');
  [['USUARIOS', USU], ['PERFIS', ['perfil', 'descricao', 'modulos']], ['LOG', ['data', 'tipo', 'usuario', 'detalhe']]].forEach(([n, cab]) => {
    const s = ss.getSheetByName(n) || ss.insertSheet(n);
    if (s.getLastRow() === 0) s.appendRow(cab);
  });
  if (!lerPerfis_().some(p => p.modulos.indexOf('*') >= 0))
    ss.getSheetByName('PERFIS').appendRow(['Administrador', 'Acesso total', '*']);
  // Aba das cláusulas do contrato (preenchida com o modelo se estiver vazia) e modelos de PMOC que faltarem
  try { garantirDadosEmpresa_(); } catch (e) { console.log('Dados da empresa: ' + e.message); }
  try { abaClausulas_(); } catch (e) { console.log('Cláusulas: ' + e.message); }
  try { instalarModelosPmoc(); } catch (e) { console.log('Modelos de PMOC: ' + e.message); }
  try { abaBanco_(); } catch (e) { console.log('Banco de itens: ' + e.message); }
  if (lerUsuarios_().some(u => normalizar_(u.login) === 'ADMIN')) {
    console.log('O usuário "admin" já existe. Para zerar a senha dele, use redefinirSenhaAdmin().');
    return;
  }
  const temp = senhaTemporaria_();
  const salt = novoSal_();
  gravarUsuario_({ login: 'admin', nome: 'Administrador', email: Session.getEffectiveUser().getEmail(), perfil: 'Administrador',
    modulos_extras: '', tecnico: '', funcionario: '', salt: salt, hash: hashSenha_(temp, salt), ativo: true,
    trocar_senha: true, criado_em: new Date(), ultimo_acesso: '' });
  console.log('Usuário: admin   Senha temporária: ' + temp + '   (o sistema vai pedir para trocar no primeiro acesso)');
}

/** RODE NO EDITOR se perder a senha do admin. */
function redefinirSenhaAdmin() {
  soDono_();
  const u = lerUsuarios_().find(x => normalizar_(x.login) === 'ADMIN');
  if (!u) throw new Error('Usuário admin não existe. Rode configuracaoInicial().');
  const temp = senhaTemporaria_();
  u.salt = novoSal_(); u.hash = hashSenha_(temp, u.salt); u.trocar_senha = true; u.ativo = true;
  gravarUsuario_(u);
  CacheService.getScriptCache().remove('TENT_ADMIN');
  console.log('Nova senha temporária do admin: ' + temp);
}
/** ===== RODE NO EDITOR: define a senha de qualquer usuário =====
 * 1. Troque o texto entre aspas em SENHA pela senha que quiser (mínimo 6 caracteres).
 * 2. Escolha "definirSenha" no menu de funções e clique em Executar.
 * 3. Depois apague a senha daqui de dentro (volte para 'escreva-aqui').
 */
function definirSenha() {
  const LOGIN = 'admin';
  const SENHA = 'escreva-aqui';
  soDono_();
  if (SENHA === 'escreva-aqui' || SENHA.trim().length < CFG.LOGIN.SENHA_MIN) throw new Error('Escreva a senha nova em SENHA (mínimo 6 caracteres).');
  const u = lerUsuarios_().find(x => normalizar_(x.login) === normalizar_(LOGIN));
  if (!u) throw new Error('Usuário "' + LOGIN + '" não existe.');
  u.salt = novoSal_(); u.hash = hashSenha_(SENHA.trim(), u.salt); u.trocar_senha = false; u.ativo = true;
  gravarUsuario_(u);
  CacheService.getScriptCache().remove('TENT_' + normalizar_(LOGIN).replace(/\s/g, ''));
  log_('SENHA_DEFINIDA_NO_EDITOR', u.login, '');
  console.log('Pronto. Entre com usuário "' + u.login + '" e a senha que você escreveu.');
}
function senhaTemporaria_() { return 'NG-' + Utilities.getUuid().replace(/-/g, '').slice(0, 8); }

/* ===== Clausulas.gs ===== */
/** ===================== CLÁUSULAS DO CONTRATO =====================
 * Ficam na planilha "Sistema NG", aba CLÁUSULAS DO CONTRATO. Edite lá: o próximo contrato gerado já sai com o texto novo.
 * Colunas: ID | Ordem | Título | Texto | Vale para | Ativo?  (também dá para editar no sistema: Dados da empresa > Cláusulas do contrato)
 *  - Vale para: Todos · Contínuo (mensal, PMOC, anual…) · Serviço único · PMOC
 *  - No texto dá para usar estes campos, que o sistema troca pelos dados do contrato:
 *    {VALOR} {VALOR_EXTENSO} {PERIODO} {DIA_VENCIMENTO} {FORMA} {INICIO} {FIM} {ATE} {AVISO_DIAS} {FORO}
 *    {GARANTIA} {RESPONSAVEL_TECNICO} {REGISTRO_RT} {ART} {ORCAMENTO} {SERVICOS}
 *  - {SERVICOS} coloca a lista de serviços e a tabela do orçamento logo depois da cláusula.
 * Se a aba estiver vazia, o sistema preenche com o modelo abaixo.
 * IMPORTANTE: é um modelo. Peça a um advogado para revisar antes de usar com clientes.
 */
const CAB_CLAUSULAS = ['ID', 'Ordem', 'Título', 'Texto', 'Vale para', 'Ativo?'];
const LINHAS_CLAUSULAS = 80; // linhas com código (CLA-001…) prontas para novas cláusulas
const CLAUSULAS_PADRAO = [
  ['Do objeto', 'Todos', 'A CONTRATADA prestará à CONTRATANTE os serviços de climatização descritos abaixo{ORCAMENTO}:{SERVICOS}'],
  ['Do valor e do pagamento', 'Serviço único', 'Pelos serviços, a CONTRATANTE pagará o valor total de {VALOR} ({VALOR_EXTENSO}), com vencimento no dia {DIA_VENCIMENTO}{FORMA}. Peças, materiais, gás refrigerante e serviços que não constem do objeto serão orçados à parte e só serão executados após a aprovação da CONTRATANTE.'],
  ['Do valor e do pagamento', 'Contínuo', 'Pelos serviços, a CONTRATANTE pagará o valor {PERIODO} de {VALOR} ({VALOR_EXTENSO}), com vencimento todo dia {DIA_VENCIMENTO}{FORMA}. Peças, materiais, gás refrigerante e serviços que não constem do objeto serão orçados à parte e só serão executados após a aprovação da CONTRATANTE.'],
  ['Do atraso no pagamento', 'Todos', 'O atraso no pagamento gera multa de 2% (dois por cento) sobre o valor devido, juros de 1% (um por cento) ao mês e correção monetária pelo IPCA. Com mais de 30 (trinta) dias de atraso, a CONTRATADA poderá suspender os serviços até a regularização, mediante aviso por escrito, sem que isso caracterize descumprimento deste contrato. Durante a suspensão, a CONTRATADA não responde pelas manutenções que deixarem de ser feitas.'],
  ['Da vigência', 'Serviço único', 'Este contrato vale até a conclusão dos serviços descritos no objeto.'],
  ['Da vigência', 'Contínuo', 'Este contrato começa em {INICIO} e vale {ATE}, podendo ser renovado por acordo entre as partes.'],
  ['Do reajuste', 'Contínuo', 'O valor será reajustado a cada 12 (doze) meses, contados do início do contrato, pela variação acumulada do IPCA (IBGE) ou, na falta dele, por outro índice oficial que o substitua.'],
  ['Das obrigações da CONTRATADA', 'Todos', 'Executar os serviços com equipe qualificada, equipamentos de proteção e ferramentas adequadas, seguindo as normas técnicas aplicáveis; registrar cada visita em ordem de serviço; informar por escrito qualquer defeito encontrado e a correção sugerida; manter sigilo sobre as informações da CONTRATANTE a que tiver acesso.'],
  ['Do PMOC', 'PMOC', 'A CONTRATADA manterá o Plano de Manutenção, Operação e Controle (PMOC), conforme a Lei nº 13.589/2018 e a Portaria GM/MS nº 3.523/1998, sob responsabilidade técnica de {RESPONSAVEL_TECNICO} ({REGISTRO_RT}), com ART/TRT nº {ART}. As rotinas e a periodicidade das atividades são definidas pelo responsável técnico. O plano e os relatórios de cada visita ficarão à disposição da CONTRATANTE e da fiscalização. Cabe à CONTRATANTE manter o plano disponível no local e permitir a execução das rotinas nas datas previstas; atividades não realizadas por falta de acesso, de liberação ou de pagamento serão registradas e não serão de responsabilidade da CONTRATADA.'],
  ['Das obrigações da CONTRATANTE', 'Todos', 'Permitir o acesso da equipe aos equipamentos nos dias e horários combinados, com um responsável no local; efetuar os pagamentos nas datas acertadas; comunicar à CONTRATADA qualquer falha nos equipamentos; não permitir que terceiros mexam nos equipamentos durante a vigência sem aviso prévio; manter a instalação elétrica, os drenos, os suportes e o local de instalação em condições adequadas.'],
  ['Da segurança e das condições do local', 'Todos', 'Os serviços seguem as normas de segurança do trabalho, em especial a NR-10 (eletricidade) e a NR-35 (trabalho em altura). A CONTRATADA poderá recusar ou adiar um serviço quando o local não oferecer condições seguras (falta de acesso, de ponto de ancoragem ou de iluminação, instalação elétrica irregular ou qualquer risco à equipe ou a terceiros), comunicando à CONTRATANTE o que precisa ser providenciado; nesse caso, o adiamento não caracteriza atraso da CONTRATADA. Andaimes, plataformas, adequações elétricas e civis não fazem parte do objeto, salvo se previstos no orçamento.'],
  ['Do estado dos equipamentos', 'Todos', 'Na primeira visita a CONTRATADA fará uma vistoria e informará por escrito os defeitos já existentes. Defeitos anteriores ao contrato não são de responsabilidade da CONTRATADA, e a sua correção será orçada à parte.'],
  ['Dos limites da responsabilidade', 'Todos', 'A CONTRATADA responde somente pelos serviços que executar. Não responde por defeitos de fabricação; danos causados por falta, oscilação ou sobrecarga de energia elétrica; mau uso; instalação elétrica ou civil inadequada; intervenção de terceiros; desgaste natural de peças; casos fortuitos ou de força maior. Eventual indenização por dano causado pela CONTRATADA fica limitada ao valor pago pelo serviço que o originou, salvo dolo ou culpa grave.'],
  ['Da garantia', 'Todos', 'A garantia é de {GARANTIA}, contada da execução de cada serviço. A garantia não cobre mau uso, falta ou oscilação de energia, intervenção de terceiros nem peças com garantia própria do fabricante, e é cancelada se outra empresa mexer no equipamento.'],
  ['Das comunicações e dos dados pessoais', 'Todos', 'Avisos e comunicações entre as partes podem ser feitos por WhatsApp ou e-mail, valendo como aviso por escrito. A CONTRATADA usará os dados da CONTRATANTE apenas para executar este contrato, emitir documentos e fazer cobranças, conforme a Lei nº 13.709/2018 (LGPD). Fotos dos equipamentos e do local podem ser feitas somente para registro técnico dos serviços.'],
  ['Da rescisão', 'Contínuo', 'Qualquer das partes pode encerrar este contrato com aviso por escrito de {AVISO_DIAS} dias, sem multa, desde que os valores até a data estejam quitados. O contrato poderá ser encerrado imediatamente, por aviso escrito, em caso de atraso no pagamento superior a 30 (trinta) dias ou de descumprimento de qualquer cláusula, sem prejuízo da cobrança dos valores devidos.'],
  ['Disposições gerais', 'Todos', 'A tolerância de uma das partes quanto ao descumprimento de qualquer cláusula não significa renúncia nem alteração deste contrato. Alterações só valem se feitas por escrito. As partes reconhecem como válida a assinatura deste contrato por meio eletrônico.'],
  ['Do foro', 'Todos', 'As partes elegem o foro da comarca de {FORO} para resolver qualquer questão sobre este contrato.']
];

function abaClausulas_() {
  const aba = abaSistema_('CLÁUSULAS DO CONTRATO', CAB_CLAUSULAS);
  if (aba.getLastRow() < 2) {
    const linhas = Array.from({ length: LINHAS_CLAUSULAS }, (_, i) => { const c = CLAUSULAS_PADRAO[i]; return ['CLA-' + String(i + 1).padStart(3, '0')].concat(c ? [(i + 1) * 10, c[0], c[2], c[1], 'Sim'] : ['', '', '', '', '']); });
    aba.getRange(2, 1, linhas.length, CAB_CLAUSULAS.length).setValues(linhas);
  }
  return aba;
}
function lerClausulas_() {
  const v = abaClausulas_().getDataRange().getValues(), cab = cabecalho_(v[0]);
  return v.slice(1).map(r => ({ ordem: Number(r[cab['Ordem']]) || 9999, titulo: String(r[cab['Título']] || '').trim(), texto: String(r[cab['Texto']] || '').trim(),
    vale: String(r[cab['Vale para']] || 'Todos').trim(), ativo: normalizar_(r[cab['Ativo?']]) !== 'NAO' }))
    .filter(c => c.ativo && c.titulo && c.texto).sort((a, b) => a.ordem - b.ordem);
}
/** Cláusulas que valem para este contrato, já com os campos trocados. campos: { CHAVE: html } */
function clausulasHtml_(tipo, unico, pmoc, campos, blocoServicos) {
  const vale = v => { const n = normalizar_(v); return n === 'TODOS' || n === '' || (n.indexOf('UNICO') >= 0 && unico) || (n.indexOf('CONTINUO') >= 0 && !unico) || (n === 'PMOC' && pmoc) || n === normalizar_(tipo); };
  let n = 0;
  return lerClausulas_().filter(c => vale(c.vale)).map(c => {
    let txt = h_(c.texto), depois = '';
    if (txt.indexOf('{SERVICOS}') >= 0) { txt = txt.replace('{SERVICOS}', ''); depois = blocoServicos || ''; }
    txt = txt.replace(/\{([A-Z_]+)\}/g, (m, k) => campos[k] != null ? campos[k] : m);
    return '<h2>Cláusula ' + (++n) + 'ª · ' + h_(c.titulo) + '</h2><p style="text-align:justify;margin:0 0 6px">' + txt + '</p>' + depois;
  }).join('');
}

/* ===== Codigo.gs ===== */
/** ===================== ENTRADA DO SISTEMA ===================== */
function doGet(e) {
  // O site público busca aqui os dados de contato (só os campos marcados "Vai para o site? = Sim").
  // Mural do site: fotos recentes do Instagram (o token fica só aqui, na aba DADOS; o site nunca vê).
  if (e && e.parameter && e.parameter.dados === 'insta') {
    let o = { fotos: [] };
    try { o = instaFotos_(); } catch (x) { }
    return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
  }
  if (e && e.parameter && e.parameter.dados === 'site') {
    let o = {};
    try { o = dadosSite_(); } catch (x) { }
    return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
  }
  return HtmlService.createTemplateFromFile('Index').evaluate()
    .setTitle('NG Ar Condicionado · Sistema')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, viewport-fit=cover')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL); // permite embutir no Google Sites
}
function include_(nome) { return HtmlService.createHtmlOutputFromFile(nome).getContent(); }

/** Ações automáticas (atualização do painel, sininho) não entram no registro de requisições. */
const SEM_REGISTRO = { notificacoes: 1, erroTela: 1 };

/** Único ponto de entrada da interface: confere sessão e permissão ANTES de qualquer operação. */
function chamarApi(acao, token, dados) {
  let u = null;
  const t0 = Date.now();
  dados = dados || {};
  const auto = !!dados._auto;
  try {
    const regra = PERMISSOES[acao];
    if (!regra || typeof globalThis[acao + '_'] !== 'function') throw erroUsuario_('Operação não permitida.');
    u = validarSessao_(token);
    if (regra === 'tabela') {
      const mod = moduloDaTabela_(dados.tabela);
      if (!mod || u.modulos.indexOf(mod) < 0) throw erroUsuario_('Você não tem acesso a este módulo.');
    } else if (regra !== '*') {
      const precisa = Array.isArray(regra) ? regra : [regra];
      if (!precisa.some(m => u.modulos.indexOf(m) >= 0)) throw erroUsuario_('Você não tem acesso a este módulo.');
    }
    const r = globalThis[acao + '_'](u, dados);
    if (!auto && !SEM_REGISTRO[acao]) requisicao_(u.login, acao, dados, Date.now() - t0, 'ok');
    return { ok: true, dados: r };
  } catch (e) {
    const msg = e && e.usuario ? e.message : String(e && e.stack || e);
    if (!e || !e.usuario) log_('ERRO', u ? u.login : '-', acao + ': ' + msg);
    if (!e || !e.sessao) requisicao_(u ? u.login : '-', acao, dados, Date.now() - t0, (e && e.usuario ? 'aviso: ' : 'ERRO: ') + msg);
    return { ok: false, erro: e && e.usuario ? e.message : 'Algo deu errado. Tente de novo em instantes.', sessao: !!(e && e.sessao) };
  }
}

/** Registro de todas as requisições (aba REQUISIÇÕES da planilha Sistema NG). */
function requisicao_(login, acao, dados, ms, resultado) {
  const det = [dados.tabela, dados.id, dados.os, dados.acao].filter(Boolean).join(' ').slice(0, 200);
  const linha = [new Date().toISOString(), String(login), String(acao), det, ms, String(resultado).slice(0, 500)];
  // Guarda em lote e grava de 25 em 25 (ou a cada 2 minutos): uma escrita na planilha em vez de uma por clique.
  const lock = LockService.getScriptLock();
  try {
    if (!lock.tryLock(1500)) { gravarRequisicoes_([linha]); return; }
    const c = CacheService.getScriptCache();
    const buf = JSON.parse(c.get('REQBUF') || '[]'); buf.push(linha);
    if (buf.length >= 25 || /^ERRO/.test(String(resultado)) || Date.now() - new Date(buf[0][0]).getTime() > 120000) { gravarRequisicoes_(buf); c.remove('REQBUF'); }
    else c.put('REQBUF', JSON.stringify(buf), 600);
  } catch (e) { console.error(e); } finally { try { lock.releaseLock(); } catch (e) { } }
}
function gravarRequisicoes_(linhas) {
  try {
    const aba = abaSistema_('REQUISIÇÕES', ['data', 'usuario', 'acao', 'detalhe', 'ms', 'resultado']);
    const n0 = aba.getLastRow();
    aba.getRange(n0 + 1, 1, linhas.length, 6).setValues(linhas.map(l => [new Date(l[0])].concat(l.slice(1))));
    const n = n0 + linhas.length;
    if (n > CFG.REQUISICOES_MAX + 1 && aba.deleteRows) aba.deleteRows(2, n - CFG.REQUISICOES_MAX);
  } catch (e) { console.error(e); }
}
/** Grava o que ainda está no lote (o registro chama antes de mostrar a lista). */
function descarregarRequisicoes_() {
  const c = CacheService.getScriptCache(), buf = JSON.parse(c.get('REQBUF') || '[]');
  if (buf.length) { gravarRequisicoes_(buf); c.remove('REQBUF'); }
}
/** Erro que aconteceu na tela (navegador) e foi avisado ao servidor. */
function erroTela_(u, d) { log_('ERRO_TELA', u.login, String(d.msg || '').slice(0, 900)); return true; }

/** Abre (ou cria) uma aba da planilha Sistema NG. */
function abaSistema_(nome, cab) {
  const ss = planilha_('SISTEMA');
  let s = ss.getSheetByName(nome);
  if (!s) { s = ss.insertSheet(nome); s.appendRow(cab); }
  return s;
}

/** O que a tela precisa saber logo depois do login. */
function contexto_(u) {
  const tabs = {};
  u.modulos.forEach(m => {
    const def = MODULOS[m];
    [def.tabela].concat(def.tabelas || []).filter(Boolean).forEach(t => { tabs[t] = definicaoPublica_(t); });
  });
  return {
    nome: String(u.nome || u.login), login: String(u.login), perfil: String(u.perfil),
    trocarSenha: String(u.trocar_senha).toUpperCase() === 'TRUE' || u.trocar_senha === true,
    modulos: u.modulos.map(m => Object.assign({ id: m }, MODULOS[m])),
    tabelas: tabs,
    sessao: { fimMax: u._sessao.inicio + CFG.SESSAO.MAX_SEG * 1000, ociosaMin: CFG.SESSAO.OCIOSA_MIN },
    sobre: { versao: CFG.VERSAO, compilacao: CFG.COMPILACAO, data: CFG.DATA_VERSAO, dev: CFG.DESENVOLVEDOR, empresa: CFG.EMPRESA.razao },
    aceite: aceiteDe_(u.login)
  };
}
/** Aviso de rastreamento: cada usuário aceita uma vez (fica guardado nas propriedades do script e no LOG). */
function aceiteDe_(login) { try { return PropertiesService.getScriptProperties().getProperty('ACEITE_' + normalizar_(login)) || ''; } catch (e) { return ''; } }
function aceitarTermo_(u) {
  const quando = agoraTxt_() + ' · versão ' + CFG.VERSAO;
  PropertiesService.getScriptProperties().setProperty('ACEITE_' + normalizar_(u.login), quando);
  log_('ACEITE_TERMO', u.login, 'Aceitou o aviso de registro de acessos e ações · ' + quando);
  return { aceite: quando };
}

/** ---------- Utilidades ---------- */
const _planilhas = {};
function planilha_(qual) { return _planilhas[qual] || (_planilhas[qual] = SpreadsheetApp.openById(idDe_(qual))); }
function erroUsuario_(msg) { const e = new Error(msg); e.usuario = true; return e; }
function normalizar_(s) { return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/\s+/g, ' ').trim().toUpperCase(); }
function hoje_() { const d = new Date(); return new Date(d.getFullYear(), d.getMonth(), d.getDate()); }
function fmtData_(d) { return Utilities.formatDate(d, CFG.FUSO, 'yyyy-MM-dd'); }
function agoraTxt_() { return Utilities.formatDate(new Date(), CFG.FUSO, 'dd/MM/yyyy HH:mm'); }
function comTrava_(fn) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(20000)) throw erroUsuario_('O sistema está ocupado. Tente de novo em alguns segundos.');
  try { return fn(); } finally { lock.releaseLock(); }
}

/** ===================== CONTATOS DO SITE =====================
 * O site manda um aviso quando alguém toca em WhatsApp, e-mail, telefone ou envia o formulário.
 * Segurança: só ACRESCENTA uma linha (não lê nem devolve nada), limita tamanho e quantidade por minuto.
 */
function doPost(e) {
  const fim = ContentService.createTextOutput('ok');
  try {
    if (!CFG.CONTATOS_SITE) return fim;
    const bruto = String(e && e.postData && e.postData.contents || '').slice(0, 4000);
    const d = JSON.parse(bruto || '{}');
    if (d.site !== 'ng' || d.empresa) return fim;                     // "empresa" é um campo escondido (armadilha para robôs)
    const tipos = { whatsapp: 'WhatsApp', email: 'E-mail', telefone: 'Telefone', formulario: 'Formulário', mapa: 'Mapa' };
    if (!tipos[d.tipo]) return fim;
    const cache = CacheService.getScriptCache();
    const k = 'SITE_' + Math.floor(Date.now() / 60000);
    const n = Number(cache.get(k) || 0);
    if (n >= 30) return fim;                                           // no máximo 30 avisos por minuto
    cache.put(k, String(n + 1), 120);
    const limpo = v => String(v || '').replace(/^[=+\-@\s]+/, '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 300);
    abaSistema_('CONTATOS DO SITE', ['data', 'tipo', 'nome', 'telefone', 'servico', 'mensagem', 'botao', 'visto'])
      .appendRow([new Date(), tipos[d.tipo], limpo(d.nome), limpo(d.tel), limpo(d.serv), String(limpo(d.msg)).slice(0, 300), limpo(d.botao), false]);
  } catch (x) { console.error(x); }
  return fim;
}

/* ===== Config.gs ===== */
/** ===================== CONFIGURAÇÃO DO SISTEMA NG =====================
 * Tudo que muda de uma instalação para outra fica aqui.
 * Quando a empresa copiar as planilhas para a conta dela, troque só os IDs abaixo.
 */
const CFG = {
  NOME: 'NG Ar Condicionado',
  // Versão mostrada em "Sobre o sistema". Compilação = número de ajustes feitos até aqui.
  VERSAO: '1.0', COMPILACAO: 40, DATA_VERSAO: '21/11/2026',
  DESENVOLVEDOR: { nome: 'Irving', email: 'jaimeirvin22@gmail.com', whatsapp: '' }, // whatsapp: só números, com 55
  FUSO: 'America/Sao_Paulo',
  IDS: {
    SISTEMA:    'DEMO_SISTEMA', // Sistema NG (controle): usuários, perfis, log
    OPERACAO:   'DEMO_OPERACAO', // Operação NG
    EQUIPE:     'DEMO_EQUIPE', // Equipe NG
    FINANCEIRO: 'DEMO_FINANCEIRO', // Financeiro NG
    PASTA_FOTOS:'DEMO_PASTA_FOTOS',           // 04 Documentos / Fotos dos serviços
    PASTA_DOCS: 'DEMO_PASTA_DOCS'            // 04 Documentos (Orçamentos, Contratos...)
  },
  LOGIN: { MAX_TENTATIVAS: 5, BLOQUEIO_SEG: 600, ITERACOES: 400, SENHA_MIN: 6 },
  SESSAO: { MAX_SEG: 21600, OCIOSA_MIN: 120 },   // 6 h no máximo, 2 h parado
  FOTO_MAX_MB: 8,
  // Contatos vindos do site (botões de WhatsApp, e-mail e formulário). false = desliga.
  CONTATOS_SITE: true,
  // Quantas linhas o registro de requisições guarda antes de apagar as mais antigas.
  REQUISICOES_MAX: 20000,
  // Dados que vão no comprovante do serviço.
  EMPRESA: { razao: 'NG Ar Condicionado LTDA', cnpj: '57.334.048/0001-53', fone: '(34) 99777-7533',
    email: 'ngarcondicionado25@gmail.com', endereco: 'Rua do Conde, 866, Pacaembu, Uberlândia/MG' }
};

/** Módulos do sistema. Cada usuário recebe os módulos do perfil + os extras dele.
 *  grupo: só para organizar o menu. tabela(s): abas que o módulo pode ler e gravar. */
const MODULOS = {
  painel:       { nome: 'Painel', curto: 'Painel',            icone: 'painel',  grupo: 'Início' },
  agenda:       { nome: 'Minha agenda', curto: 'Agenda',      icone: 'agenda',  grupo: 'Início' },
  ponto:        { nome: 'Meu ponto', curto: 'Ponto',          icone: 'relogio', grupo: 'Início' },
  servicos:     { nome: 'Serviços (OS)', curto: 'Serviços',   icone: 'chave',   grupo: 'Operação', tabela: 'SERVICOS' },
  orcamentos:   { nome: 'Orçamentos', curto: 'Orçam.',        icone: 'orcamento', grupo: 'Operação', tabela: 'ORCAMENTOS', tabelas: ['PRECOS'] },
  clientes:     { nome: 'Clientes e contratos', curto: 'Clientes', icone: 'pessoas', grupo: 'Operação', tabela: 'CLIENTES', tabelas: ['CONTRATOS'] },
  equipamentos: { nome: 'Equipamentos', curto: 'Equip.',      icone: 'ar',      grupo: 'Operação', tabela: 'EQUIPAMENTOS' },
  pmoc:         { nome: 'PMOC', curto: 'PMOC',                icone: 'check',   grupo: 'Operação', tabela: 'PMOC', tabelas: ['CHECKLIST', 'TIPOS_EQ', 'BANCO'] },
  estoque:      { nome: 'Estoque', curto: 'Estoque',          icone: 'caixa',   grupo: 'Operação', tabela: 'ESTOQUE' },
  contatos:     { nome: 'Contatos do site', curto: 'Contatos', icone: 'sino',   grupo: 'Operação' },
  financeiro:   { nome: 'Movimento', curto: 'Movimento',      icone: 'dinheiro',grupo: 'Financeiro', tabela: 'MOVIMENTO' },
  fixas:        { nome: 'Despesas fixas', curto: 'Fixas',     icone: 'repetir', grupo: 'Financeiro', tabela: 'FIXAS' },
  reserva:      { nome: 'Reserva', curto: 'Reserva',          icone: 'cofre',   grupo: 'Financeiro', tabela: 'RESERVA' },
  equipe:       { nome: 'Funcionários', curto: 'Equipe',      icone: 'pessoas', grupo: 'Equipe', tabela: 'FUNCIONARIOS' },
  controle:     { nome: 'Controle de funcionários', curto: 'Controle', icone: 'prancheta', grupo: 'Equipe', tabelas: ['PRESENCA', 'PONTO'] },
  usuarios:     { nome: 'Usuários e perfis', curto: 'Usuários', icone: 'cadeado', grupo: 'Administração' },
  config:       { nome: 'Dados da empresa', curto: 'Dados',   icone: 'engrenagem', grupo: 'Administração', tabelas: ['CLAUSULAS'] }
};
/** Nomes antigos de módulo que ainda podem estar gravados nos perfis. */
const MODULOS_ANTIGOS = { pontoEquipe: 'controle' };

/** Operações que o navegador pode pedir e o módulo exigido.
 *  '*' = qualquer usuário logado. 'tabela' = depende da tabela pedida. */
const PERMISSOES = {
  contexto: '*', trocarSenha: '*', notificacoes: '*', erroTela: '*',
  listar: 'tabela', salvar: 'tabela', limpar: 'tabela', avisosExcluir: 'tabela', aceitarTermo: '*',
  painel: 'painel',
  pontoHoje: 'ponto', pontoRegistrar: 'ponto',
  presencaDia: 'controle', presencaSalvar: 'controle', controleResumo: 'controle',
  agenda: 'agenda', agendaAcao: ['agenda', 'servicos'], servicoInfo: ['agenda', 'servicos'],
  fotoEnviar: ['agenda', 'servicos', 'equipamentos', 'clientes', 'financeiro', 'fixas', 'reserva'],
  fotosListar: ['agenda', 'servicos', 'equipamentos', 'clientes', 'financeiro', 'fixas', 'reserva'],
  assinaturaEnviar: ['agenda', 'servicos'], comprovanteGerar: ['agenda', 'servicos'], prefetch: '*',
  materiaisListar: ['agenda', 'servicos'], materialAdicionar: ['agenda', 'servicos'], materialRemover: ['agenda', 'servicos'],
  movimentoPagar: 'financeiro', fixaPagarMes: 'fixas', reciboGerar: 'financeiro', contadorRelatorio: 'financeiro', pixGerar: ['financeiro', 'orcamentos', 'agenda', 'servicos'],
  arquivoVer: '*',
  contratoGerar: 'clientes', orcamentoInfo: 'orcamentos', orcamentoSalvar: 'orcamentos', orcamentoPdf: 'orcamentos', orcamentoAprovar: 'orcamentos', fecharNegocio: 'orcamentos', boletoSalvar: 'financeiro',
  pmocContrato: ['pmoc', 'clientes'], pmocVincular: ['pmoc', 'clientes'], pmocChecklist: ['pmoc', 'agenda', 'servicos'], pmocRegistrar: ['pmoc', 'agenda', 'servicos'],
  checklistCopiar: 'pmoc', pmocPlano: ['pmoc', 'clientes'], pmocRelatorio: ['pmoc', 'clientes', 'servicos'], clienteResumo: ['clientes', 'orcamentos'],
  dadosLer: 'config', dadosSalvar: 'config', acessoFuncionario: 'usuarios',
  contatosListar: 'contatos', contatoVisto: 'contatos',
  usuariosListar: 'usuarios', usuarioSalvar: 'usuarios', usuarioSenha: 'usuarios',
  perfisListar: 'usuarios', perfilSalvar: 'usuarios', logListar: 'usuarios'
};

/* ===== Contador.gs ===== */
/** ===================== RELATÓRIOS PARA O CONTADOR =====================
 * Mensal (ex.: 2025-09) ou anual (ex.: 2025). Gera, na pasta do financeiro > "Relatórios do contador":
 *  - um PDF para leitura (resumo, totais por categoria, lista de lançamentos com links dos comprovantes);
 *  - uma planilha do Google com os mesmos lançamentos (o contador pode baixar como Excel).
 * Entram os lançamentos da aba MOVIMENTO (menos "Saldo inicial") e as despesas fixas marcadas como pagas.
 * Obs.: as despesas fixas só guardam o mês (Jan…Dez) do ano atual, então só entram no relatório do ano atual.
 */
const CAB_CONTADOR = ['Data', 'Entrada ou saída', 'Descrição', 'Categoria', 'Forma de pagamento', 'Valor', 'Situação', 'Vínculo', 'Comprovante', 'Recibo', 'Boleto', 'ID'];

function garantirDado_(campo, ajuda) {
  if (dadosEmpresa_()[campo]) return;
  abaDados_().appendRow([campo, '', ajuda || '', 'Não']);
  CacheService.getScriptCache().remove('DADOS_EMP'); _dados = null;
}

/** Junta lançamentos e despesas fixas do período. periodo = 'aaaa' ou 'aaaa-mm'. */
function contadorDados_(periodo) {
  const ano = +periodo.slice(0, 4), mesSo = periodo.length === 7 ? +periodo.slice(5, 7) : 0;
  const dentro = data => String(data || '').indexOf(periodo) === 0;
  const linhas = lerTabela_('MOVIMENTO')
    .filter(m => m['Categoria'] !== 'Saldo inicial' && dentro(m['Data']) && !exemplo_(m['Descrição']))
    .map(m => ({ data: String(m['Data']).slice(0, 10), entrada: m['Entrada ou saída'] === 'Entrada', desc: String(m['Descrição'] || ''), cat: String(m['Categoria'] || 'Outros'),
      forma: String(m['Forma de pagamento'] || ''), valor: num_(m['Valor']) || 0, pago: !!m['Pago?'], vinc: String(m['Vínculo (OS, cliente, funcionário)'] || ''),
      comp: String(m['Comprovante'] || ''), recibo: String(m['Recibo'] || ''), boleto: String(m['Boleto'] || ''), id: m._id }));
  const anoAtual = hoje_().getFullYear();
  let semFixas = false;
  if (ano === anoAtual) {
    lerTabela_('FIXAS').filter(f => !exemplo_(f['Despesa fixa'])).forEach(f => {
      MESES.forEach((nomeMes, i) => {
        if (!f[nomeMes] || (mesSo && i + 1 !== mesSo)) return;
        const dia = Math.min(Math.max(Number(f['Dia']) || 1, 1), new Date(ano, i + 1, 0).getDate());
        linhas.push({ data: ano + '-' + String(i + 1).padStart(2, '0') + '-' + String(dia).padStart(2, '0'), entrada: false, desc: String(f['Despesa fixa']) + ' (despesa fixa)', cat: 'Despesas fixas',
          forma: '', valor: num_(f['Valor']) || 0, pago: true, vinc: '', comp: String(f['Comprovantes'] || ''), recibo: '', boleto: '', id: f._id });
      });
    });
  } else semFixas = true;
  linhas.sort((a, b) => a.data < b.data ? -1 : a.data > b.data ? 1 : 0);
  const pagas = linhas.filter(l => l.pago);
  const soma = ls => Math.round(ls.reduce((s, l) => s + l.valor, 0) * 100) / 100;
  const porChave = (ls, k) => { const o = {}; ls.forEach(l => { const c = l[k] || 'Não informado'; o[c] = (o[c] || 0) + l.valor; }); return Object.keys(o).sort((a, b) => o[b] - o[a]).map(c => [c, Math.round(o[c] * 100) / 100]); };
  const ent = pagas.filter(l => l.entrada), sai = pagas.filter(l => !l.entrada);
  const r = {
    periodo: periodo, anual: !mesSo, titulo: mesSo ? mesTxt_(periodo) : 'ano de ' + ano, linhas: linhas, semFixas: semFixas,
    entradas: soma(ent), saidas: soma(sai), aReceber: soma(linhas.filter(l => l.entrada && !l.pago)), aPagar: soma(linhas.filter(l => !l.entrada && !l.pago)),
    catEnt: porChave(ent, 'cat'), catSai: porChave(sai, 'cat'), formas: porChave(ent, 'forma')
  };
  r.resultado = Math.round((r.entradas - r.saidas) * 100) / 100;
  if (!mesSo) {
    r.meses = MESES_PT.map((nome, i) => {
      const p = ano + '-' + String(i + 1).padStart(2, '0'), ls = pagas.filter(l => l.data.indexOf(p) === 0);
      const e = soma(ls.filter(l => l.entrada)), s = soma(ls.filter(l => !l.entrada));
      return { mes: nome, entradas: e, saidas: s, resultado: Math.round((e - s) * 100) / 100 };
    });
  }
  return r;
}

function contadorHtml_(r) {
  const lnk = (u, t) => u ? '<a href="' + h_(u) + '" style="color:#0789aa">' + t + '</a>' : '';
  const tabCat = (titulo, ls) => '<h2>' + titulo + '</h2>' + (ls.length ? '<table><tr><th>Categoria</th><th class="n">Valor</th></tr>' +
    ls.map(([c, v]) => '<tr><td>' + h_(c) + '</td><td class="n">' + brl_(v) + '</td></tr>').join('') + '</table>' : '<div class="sub">Nada no período.</div>');
  const resumo = '<table style="font-size:11pt"><tr><td class="r">Entradas recebidas</td><td class="n" style="color:#1d7a4b"><b>' + brl_(r.entradas) + '</b></td></tr>' +
    '<tr><td class="r">Saídas pagas</td><td class="n" style="color:#c0392b"><b>' + brl_(r.saidas) + '</b></td></tr>' +
    '<tr><td class="r">Resultado do período</td><td class="n"><b>' + brl_(r.resultado) + '</b></td></tr>' +
    '<tr><td class="r">Ainda a receber</td><td class="n">' + brl_(r.aReceber) + '</td></tr><tr><td class="r">Ainda a pagar</td><td class="n">' + brl_(r.aPagar) + '</td></tr></table>';
  const meses = r.meses ? '<h2>Mês a mês</h2><table><tr><th>Mês</th><th class="n">Entradas</th><th class="n">Saídas</th><th class="n">Resultado</th></tr>' +
    r.meses.map(m => '<tr><td>' + h_(m.mes) + '</td><td class="n">' + brl_(m.entradas) + '</td><td class="n">' + brl_(m.saidas) + '</td><td class="n">' + brl_(m.resultado) + '</td></tr>').join('') +
    '<tr><th>Total</th><th class="n">' + brl_(r.entradas) + '</th><th class="n">' + brl_(r.saidas) + '</th><th class="n">' + brl_(r.resultado) + '</th></tr></table>' : '';
  const lista = '<h2>Lançamentos</h2>' + (r.linhas.length ? '<table style="font-size:8.5pt"><tr><th>Data</th><th>Descrição</th><th>Categoria</th><th>Forma</th><th class="n">Valor</th><th>Situação</th><th>Arquivos</th></tr>' +
    r.linhas.map(l => '<tr><td style="white-space:nowrap">' + h_(dtBR_(l.data)) + '</td><td>' + h_(l.desc || '—') + (l.vinc ? '<br><small style="color:#5f717a">' + h_(l.vinc) + '</small>' : '') + '</td><td>' + h_(l.cat) + '</td><td>' + h_(l.forma) + '</td>' +
      '<td class="n" style="color:' + (l.entrada ? '#1d7a4b' : '#c0392b') + '">' + (l.entrada ? '+' : '−') + brl_(l.valor) + '</td><td>' + (l.pago ? (l.entrada ? 'Recebido' : 'Pago') : (l.entrada ? 'A receber' : 'A pagar')) + '</td>' +
      '<td>' + [lnk(l.comp, 'comprovante'), lnk(l.recibo, 'recibo'), lnk(l.boleto, 'boleto')].filter(Boolean).join(' · ') + '</td></tr>').join('') + '</table>' : '<div class="sub">Nenhum lançamento no período.</div>');
  return '<h2>Resumo</h2>' + resumo + meses + tabCat('Entradas por categoria', r.catEnt) + tabCat('Saídas por categoria', r.catSai) + tabCat('Entradas por forma de pagamento', r.formas) + lista +
    (r.semFixas ? '<div class="sub">As despesas fixas não entram neste relatório porque a aba FIXAS só guarda os meses do ano atual. Elas aparecem na lista se tiverem sido lançadas no Movimento.</div>' : '') +
    '<div class="sub">Valores em reais. "Entradas recebidas" e "Saídas pagas" contam só o que foi confirmado. Os links abrem os comprovantes, recibos e boletos no Google Drive.</div>';
}

/** Planilha do Google com os lançamentos e o resumo, na mesma pasta do PDF. */
function contadorPlanilha_(r, pasta, nome) {
  const velhos = pasta.getFilesByName(nome);
  while (velhos.hasNext()) velhos.next().setTrashed(true);
  const ss = SpreadsheetApp.create(nome);
  const lan = ss.getSheets()[0]; lan.setName('LANÇAMENTOS');
  const dt = s => { const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? new Date(+m[1], +m[2] - 1, +m[3]) : s; };
  const linhas = r.linhas.map(l => [dt(l.data), l.entrada ? 'Entrada' : 'Saída', l.desc, l.cat, l.forma, l.entrada ? l.valor : -l.valor,
    l.pago ? (l.entrada ? 'Recebido' : 'Pago') : (l.entrada ? 'A receber' : 'A pagar'), l.vinc, l.comp, l.recibo, l.boleto, l.id]);
  lan.getRange(1, 1, 1, CAB_CONTADOR.length).setValues([CAB_CONTADOR]);
  if (linhas.length) {
    lan.getRange(2, 1, linhas.length, CAB_CONTADOR.length).setValues(linhas);
    lan.getRange(2, 1, linhas.length, 1).setNumberFormat('dd/MM/yyyy');
    lan.getRange(2, 6, linhas.length, 1).setNumberFormat('"R$" #,##0.00;-"R$" #,##0.00');
  }
  const res = ss.insertSheet('RESUMO');
  const v = [['Relatório para o contador', r.titulo], ['Entradas recebidas', r.entradas], ['Saídas pagas', r.saidas], ['Resultado', r.resultado], ['Ainda a receber', r.aReceber], ['Ainda a pagar', r.aPagar], ['', '']]
    .concat([['ENTRADAS POR CATEGORIA', '']], r.catEnt, [['', ''], ['SAÍDAS POR CATEGORIA', '']], r.catSai, [['', ''], ['ENTRADAS POR FORMA DE PAGAMENTO', '']], r.formas);
  if (r.meses) { v.push(['', ''], ['MÊS', 'RESULTADO']); r.meses.forEach(m => v.push([m.mes + ' (entradas ' + m.entradas + ' / saídas ' + m.saidas + ')', m.resultado])); }
  res.getRange(1, 1, v.length, 2).setValues(v);
  res.getRange(2, 2, v.length - 1, 1).setNumberFormat('"R$" #,##0.00;-"R$" #,##0.00');
  const arq = DriveApp.getFileById(ss.getId());
  arq.moveTo(pasta);
  try { arq.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (x) { }
  return ss.getUrl();
}

function contadorRelatorio_(u, d) {
  const periodo = String(d.periodo || '').trim();
  if (!/^\d{4}(-(0[1-9]|1[0-2]))?$/.test(periodo)) throw erroUsuario_('Escolha o mês (ex.: 2025-09) ou o ano (ex.: 2025).');
  garantirDado_('WhatsApp do contador', 'Número do contador para mandar os relatórios (só números, com 55).');
  const r = contadorDados_(periodo);
  const raiz = pastaRaiz_('fin'), pasta = subpasta_(raiz, 'Relatórios do contador', true);
  const nome = (r.anual ? 'Contador NG - anual ' + periodo : 'Contador NG - mensal ' + periodo);
  const pdf = salvarPdf_(pasta, nome + '.pdf', docHtml_('Relatório para o contador · ' + r.titulo, emp_('Razão social') + ' · CNPJ ' + emp_('CNPJ'), contadorHtml_(r)));
  let planilha = '', erroPlanilha = '';
  try { planilha = contadorPlanilha_(r, pasta, nome); } catch (x) { erroPlanilha = 'A planilha não pôde ser criada (' + (x.message || x) + '). O PDF foi gerado.'; }
  log_('CONTADOR', u.login, periodo);
  return { url: pdf.url, publico: pdf.publico, cliente: 'o contador', semTel: 'Para mandar direto ao contador, cadastre o número dele em Dados da empresa (linha "WhatsApp do contador").', planilha: planilha, erroPlanilha: erroPlanilha, pasta: pasta.getUrl(), titulo: r.titulo, anual: r.anual,
    entradas: r.entradas, saidas: r.saidas, resultado: r.resultado, lancamentos: r.linhas.length, tel: String(emp_('WhatsApp do contador') || '') };
}

/* ===== Dados.gs ===== */
/** ===================== LEITURA E GRAVAÇÃO NAS PLANILHAS ===================== */
const SO_LEITURA = { info: 1, link: 1 };

function moduloDaTabela_(tab) { return Object.keys(MODULOS).find(m => MODULOS[m].tabela === tab || (MODULOS[m].tabelas || []).indexOf(tab) >= 0); }
function defTabela_(tab) { const t = TABELAS[tab]; if (!t) throw erroUsuario_('Tabela desconhecida.'); return t; }
function abaDe_(t) {
  if (t === TABELAS.BANCO) return abaBanco_();
  const s = planilha_(t.planilha).getSheetByName(t.aba) || (t === TABELAS.CLAUSULAS ? abaClausulas_() : null);
  if (!s) throw new Error('Aba não encontrada: ' + t.aba);
  return s;
}
function definicaoPublica_(tab) {
  const t = TABELAS[tab];
  return { titulo: t.titulo, novo: t.novo, card: t.card, ordem: t.ordem || {}, id: t.id, filtros: t.filtros || [], mes: t.mes || '',
    campos: t.campos.map(c => ({ c: c.c, t: c.t, rotulo: c.rotulo || c.c, obrig: !!c.obrig, padrao: c.padrao, tel: !!c.tel, mes: c.mes, tipoInfo: c.tipoInfo, temOpcoes: !!c.opcoes })) };
}
function cabecalho_(linha) { const m = {}; linha.forEach((h, i) => { m[String(h).trim()] = i; }); return m; }

/** Converte o valor da célula para o formato que a tela usa. */
function paraTela_(campo, v, d) {
  switch (campo.t) {
    case 'data': return v instanceof Date ? fmtData_(v) : (v ? String(d) : '');
    case 'hora': return d || '';
    case 'dinheiro': case 'numero': return typeof v === 'number' ? v : (v === '' ? '' : Number(String(v).replace(',', '.')) || '');
    case 'bool': return v === true || String(v).toUpperCase() === 'TRUE';
    case 'info': return d || '';
    default: return v === null || v === undefined ? '' : String(v);
  }
}
/** Converte o que veio da tela para gravar na célula. */
function paraPlanilha_(campo, v) {
  if (v === null || v === undefined) v = '';
  switch (campo.t) {
    case 'data': {
      if (!v) return '';
      const m = String(v).match(/^(\d{4})-(\d{2})-(\d{2})/);
      if (!m) throw erroUsuario_('Data inválida em "' + campo.c + '".');
      return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
    }
    case 'hora': {
      if (!v) return '';
      if (!/^\d{1,2}:\d{2}$/.test(String(v))) throw erroUsuario_('Hora inválida em "' + campo.c + '" (use 08:30).');
      return String(v);
    }
    case 'dinheiro': case 'numero': {
      if (v === '') return '';
      if (typeof v === 'number') return v;
      const s = String(v).replace(/[R$\s]/g, '');
      const n = s.indexOf(',') >= 0 ? Number(s.replace(/\./g, '').replace(',', '.')) : Number(s);
      if (isNaN(n)) throw erroUsuario_('Número inválido em "' + campo.c + '".');
      return n;
    }
    case 'bool': return v === true || v === 'true';
    default: return String(v).slice(0, 5000);
  }
}

/** Lê a tabela inteira (só as linhas em uso). */
const _memo = {};
/** Cache das tabelas entre requisições (deixa o sistema mais rápido).
 *  Qualquer gravação pelo sistema troca a "versão" e invalida tudo na hora.
 *  Mudanças feitas direto na planilha aparecem em até 1 minuto. */
const CACHE_SEG = 60, CACHE_PARTE = 90000;
function versaoCache_() {
  const c = CacheService.getScriptCache();
  let v = c.get('VER_TAB');
  if (!v) { v = String(Date.now()); c.put('VER_TAB', v, 21600); }
  return v;
}
function esquecer_() {
  Object.keys(_memo).forEach(k => delete _memo[k]);
  try { CacheService.getScriptCache().put('VER_TAB', String(Date.now()) + Math.random().toString(36).slice(2, 6), 21600); } catch (e) { }
}
function cacheLer_(chave) {
  try {
    const c = CacheService.getScriptCache(), n = Number(c.get(chave + '_n') || 0);
    if (!n) return null;
    let txt = '';
    for (let i = 0; i < n; i++) { const p = c.get(chave + '_' + i); if (p == null) return null; txt += p; }
    return JSON.parse(txt);
  } catch (e) { return null; }
}
function cacheGravar_(chave, obj) {
  try {
    const c = CacheService.getScriptCache(), txt = JSON.stringify(obj), n = Math.ceil(txt.length / CACHE_PARTE);
    if (n > 20) return;
    for (let i = 0; i < n; i++) c.put(chave + '_' + i, txt.slice(i * CACHE_PARTE, (i + 1) * CACHE_PARTE), CACHE_SEG);
    c.put(chave + '_n', String(n), CACHE_SEG);
  } catch (e) { }
}
function lerTabela_(tab) {
  if (!_memo[tab]) { const em = cacheLer_('T_' + tab + '_' + versaoCache_()); if (em) _memo[tab] = em; }
  if (_memo[tab]) return _memo[tab].map(o => Object.assign({}, o));
  const t = defTabela_(tab), aba = abaDe_(t);
  const rng = aba.getDataRange(), v = rng.getValues(), d = rng.getDisplayValues();
  const cab = cabecalho_(v[0]);
  const iId = cab[t.id], iChave = cab[t.chave];
  if (iId === undefined || iChave === undefined) throw new Error('Cabeçalho não encontrado em ' + t.aba + ': ' + t.id + ' / ' + t.chave);
  const linhas = [];
  for (let r = 1; r < v.length; r++) {
    if (String(d[r][iChave]).trim() === '') continue;
    const o = { _id: String(v[r][iId]), _linha: r + 1 };
    t.campos.forEach(c => { const j = cab[c.c]; o[c.c] = j === undefined ? '' : paraTela_(c, v[r][j], d[r][j]); });
    linhas.push(o);
  }
  _memo[tab] = linhas;
  cacheGravar_('T_' + tab + '_' + versaoCache_(), linhas);
  return linhas.map(o => Object.assign({}, o));
}

/** Opções das listas suspensas de uma tabela. */
function opcoesDe_(tab) {
  const t = defTabela_(tab), out = {};
  const cacheLocal = {};
  t.campos.filter(c => c.opcoes).forEach(c => {
    if (Array.isArray(c.opcoes)) { out[c.c] = c.opcoes; return; }
    if (cacheLocal[c.opcoes]) { out[c.c] = cacheLocal[c.opcoes]; return; }
    let lista = [];
    if (c.opcoes === 'TECNICOS') { out[c.c] = cacheLocal[c.opcoes] = tecnicos_(); return; }
    if (c.opcoes === 'CONTRATOS') {
      const ativos = lerTabela_('CONTRATOS').filter(x => x['Situação'] !== 'Encerrado');
      out[c.c] = cacheLocal[c.opcoes] = ativos.map(x => x._id);
      out._info = out._info || {};
      out._info[c.c] = {};
      ativos.forEach(x => { out._info[c.c][x._id] = x['Cliente'] + ' · ' + x['Tipo'] + (x['Situação'] !== 'Ativo' ? ' · ' + x['Situação'] : ''); });
      return;
    }
    if (c.opcoes === 'CHECKLISTS') {
      const n = {}; lerTabela_('CHECKLIST').forEach(x => { if (x['Checklist']) n[x['Checklist']] = 1; });
      ['Split', 'Piso teto', 'Fan coil', 'Chiller'].forEach(x => n[x] = 1);
      out[c.c] = cacheLocal[c.opcoes] = Object.keys(n).sort();
      return;
    }
    if (c.opcoes === 'ORCAMENTOS') {
      const os = lerTabela_('ORCAMENTOS').filter(x => x['Situação'] !== 'Recusado');
      out[c.c] = cacheLocal[c.opcoes] = os.map(x => x._id).reverse();
      out._info = out._info || {}; out._info[c.c] = {};
      os.forEach(x => { out._info[c.c][x._id] = x['Cliente'] + ' · ' + (x['Tipo'] || 'Avulso') + ' · ' + x['Situação'] + (x['Total'] !== '' ? ' · ' + x['Total'] : ''); });
      out._orc = {}; os.forEach(x => { out._orc[x._id] = { cliente: x['Cliente'], total: num_(x['Total']) }; });
      return;
    }
    const p = c.opcoes.split(':');
    if (p[0] === 'TAB' && defTabela_(p[1]).campos.some(x => x.c === p[2])) {
      lista = Array.from(new Set(lerTabela_(p[1]).map(x => String(x[p[2]]).trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b, 'pt-BR'));
    } else if (p[0] === 'LISTAS') {
      lista = listaLISTAS_(p[1]);
    } else if (p[0] === 'TAB') {
      const tt = defTabela_(p[1]), aba = abaDe_(tt);
      const v = aba.getDataRange().getDisplayValues(), cab = cabecalho_(v[0]);
      const j = cab[p[2]];
      if (j !== undefined) lista = v.slice(1).map(r => String(r[j]).trim()).filter(Boolean);
      lista = Array.from(new Set(lista)).sort((a, b) => a.localeCompare(b, 'pt-BR'));
    }
    out[c.c] = cacheLocal[c.opcoes] = lista;
  });
  return out;
}

/** Técnicos = lista da aba LISTAS + funcionários ativos marcados como técnico de campo. */
let _listas = null;
function listaLISTAS_(cab) {
  const v = _listas || (_listas = planilha_('OPERACAO').getSheetByName('LISTAS').getDataRange().getValues());
  const j = v[0].map(h => String(h).trim()).indexOf(cab);
  return j < 0 ? [] : v.slice(1).map(r => String(r[j]).trim()).filter(Boolean);
}
function tecnicos_() {
  const nomes = listaLISTAS_('Técnicos');
  const add = n => { n = String(n || '').trim(); if (n && nomes.indexOf(n) < 0) nomes.push(n); };
  // quem tem login ativo com a "Minha agenda" liberada é técnico
  lerUsuarios_().filter(x => ativo_(x) && x.funcionario && modulosDoUsuario_(x).indexOf('agenda') >= 0).forEach(x => add(x.funcionario));
  // compatibilidade: funcionário marcado como técnico de campo na planilha
  lerTabela_('FUNCIONARIOS').forEach(f => { if (normalizar_(f['Técnico de campo?']) === 'SIM' && normalizar_(f['Ativo?']) !== 'NAO') add(f['Nome']); });
  return nomes.filter(n => !/\(apague\)/i.test(n));
}
/** Coloca o técnico na coluna "Técnicos" da aba LISTAS (para a lista da planilha também funcionar). */
function sincronizarTecnico_(nome) {
  nome = String(nome || '').trim();
  if (!nome) return;
  const aba = planilha_('OPERACAO').getSheetByName('LISTAS');
  const v = aba.getDataRange().getValues(), j = v[0].map(h => String(h).trim()).indexOf('Técnicos');
  if (j < 0) return;
  let livre = 0;
  for (let r = 1; r < v.length; r++) {
    const x = String(v[r][j]).trim();
    if (normalizar_(x) === normalizar_(nome)) return;
    if (!x && !livre) livre = r + 1;
  }
  aba.getRange(livre || v.length + 1, j + 1).setValue(nome);
  _listas = null;
}

const MESES = ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Jul', 'Ago', 'Set', 'Out', 'Nov', 'Dez'];

/** ---------- Operações chamadas pela tela ---------- */
function listar_(u, d) {
  const linhas = lerTabela_(d.tabela);
  if (d.tabela === 'CLIENTES') {
    const ct = {};
    lerTabela_('CONTRATOS').filter(x => x['Situação'] === 'Ativo').forEach(x => { (ct[x['Cliente']] = ct[x['Cliente']] || []).push(x['Tipo']); });
    linhas.forEach(l => { l._contratos = (ct[l['Nome / razão social']] || []).join(', '); });
  }
  return { linhas: linhas, opcoes: opcoesDe_(d.tabela) };
}
/** Busca várias tabelas de uma vez (usada para pré-carregar as telas logo depois do login). */
function prefetch_(u, d) {
  const out = {};
  (d.tabelas || []).slice(0, 12).forEach(t => {
    const mod = moduloDaTabela_(t);
    if (mod && u.modulos.indexOf(mod) >= 0) { try { out[t] = listar_(u, { tabela: t }); } catch (e) { } }
  });
  if (u.modulos.indexOf('painel') >= 0 && d.painel) { try { out._painel = painel_(u); } catch (e) { } }
  return out;
}

function salvar_(u, d) { return gravar_(u, d, false); }
/** interno = chamada feita pelo próprio servidor (pode gravar campos marcados como sistema). */
function gravar_(u, d, interno) {
  const t = defTabela_(d.tabela), valores = Object.assign({}, d.valores || {});
  if (!interno) t.campos.filter(c => c.sistema).forEach(c => { delete valores[c.c]; });
  // Cadastro novo: todos os obrigatórios. Edição: só confere os obrigatórios que vieram na alteração.
  t.campos.filter(c => c.obrig && (!d.id || c.c in valores)).forEach(c => {
    const v = valores[c.c];
    if (v === undefined || v === null || String(v).trim() === '') throw erroUsuario_('Preencha "' + (c.rotulo || c.c) + '".');
  });
  if (d.tabela === 'CONTRATOS' && valores['Orçamento']) {
    const o = lerTabela_('ORCAMENTOS').find(x => x._id === String(valores['Orçamento']));
    if (o) {
      const its = lerTabela_('ITENS_ORC').filter(x => x['Nº orçamento'] === o._id);
      const tot = its.reduce((s, i) => s + (Number(String(i['Quantidade']).replace(',', '.')) || 1) * num_(i['Valor unitário']), 0) - num_(o['Desconto']);
      if (valores['Valor'] === '' || valores['Valor'] == null || d.usarValorOrc) valores['Valor'] = Math.round(tot * 100) / 100;
      if (!String(valores['Serviços incluídos'] || '').trim()) valores['Serviços incluídos'] = its.map(i => i['Serviço'] + (num_(i['Quantidade']) !== 1 ? ' (' + i['Quantidade'] + ')' : '')).join('; ');
    }
  }
  if (d.tabela === 'FIXAS' && d.id && !d.liberarMeses) {
    const atual = lerTabela_('FIXAS').find(x => x._id === String(d.id));
    const mesHoje = hoje_().getMonth();
    MESES.forEach((m, i) => {
      if (i < mesHoje && atual && (m in valores) && !!valores[m] !== !!atual[m])
        throw erroUsuario_('Os meses anteriores estão travados. Toque em "Editar meses anteriores" para mudar ' + m + '.');
    });
  }
  if (d.tabela === 'FIXAS' && d.id) {
    const atual = lerTabela_('FIXAS').find(x => x._id === String(d.id)) || {};
    const mudou = MESES.filter(m => (m in valores) && !!valores[m] !== !!atual[m]);
    if (mudou.length) valores['Última baixa'] = mudou.map(m => m + (valores[m] ? ' pago' : ' desmarcado')).join(', ') + ' · ' + (u.nome || u.login) + ' · ' + Utilities.formatDate(new Date(), CFG.FUSO, 'dd/MM/yyyy HH:mm');
  }
  return comTrava_(() => {
    const aba = abaDe_(t);
    const ultima = aba.getLastRow();
    const cab = cabecalho_(aba.getRange(1, 1, 1, aba.getLastColumn()).getValues()[0]);
    const iId = cab[t.id], iChave = cab[t.chave];
    const ids = aba.getRange(1, iId + 1, ultima, 1).getValues();
    const chaves = aba.getRange(1, iChave + 1, ultima, 1).getDisplayValues();
    let linha = 0, novo = false;
    if (d.id) {
      for (let r = 1; r < ultima; r++) if (String(ids[r][0]) === String(d.id)) { linha = r + 1; break; }
      if (!linha) throw erroUsuario_('Registro não encontrado. Atualize a tela.');
    } else {
      for (let r = 1; r < ultima; r++) if (String(ids[r][0]).trim() && !String(chaves[r][0]).trim()) { linha = r + 1; break; }
      if (!linha && t.crescer) {
        // abas de configuração (checklists, tipos, cláusulas): acrescenta uma linha com o próximo código
        const ult = ids.slice(1).map(x => String(x[0] || '')).filter(Boolean).pop() || '';
        const m = ult.match(/^(.*?)(\d+)$/);
        if (m) { const novoId = m[1] + String(Number(m[2]) + 1).padStart(m[2].length, '0'); linha = ultima + 1; aba.getRange(linha, iId + 1).setValue(novoId); ids.push([novoId]); }
      }
      if (!linha) throw erroUsuario_('A planilha "' + t.aba + '" está cheia. Peça para o administrador acrescentar linhas com códigos.');
      novo = true;
    }
    // Junta as colunas vizinhas e grava cada bloco de uma vez (bem mais rápido que célula por célula).
    const col = {};
    t.campos.forEach(c => {
      if (cab[c.c] === undefined || !(c.c in valores)) return;
      if (SO_LEITURA[c.t] && !c.sistema) return;
      col[cab[c.c] + 1] = c.sistema ? String(valores[c.c]) : paraPlanilha_(c, valores[c.c]);
    });
    if (novo && cab['Origem'] !== undefined) col[cab['Origem'] + 1] = 'Sistema';
    const nums = Object.keys(col).map(Number).sort((a, b) => a - b);
    for (let i = 0; i < nums.length;) {
      let j = i; while (j + 1 < nums.length && nums[j + 1] === nums[j] + 1) j++;
      aba.getRange(linha, nums[i], 1, j - i + 1).setValues([nums.slice(i, j + 1).map(n => col[n])]);
      i = j + 1;
    }
    esquecer_();
    const id = String(ids[linha - 1][0]);
    if (d.tabela === 'FUNCIONARIOS' && normalizar_(valores['Técnico de campo?']) === 'SIM') sincronizarTecnico_(valores['Nome'] || aba.getRange(linha, cab['Nome'] + 1).getValue());
    log_(novo ? 'CRIAR' : 'EDITAR', u.login, d.tabela + ' ' + id);
    return { id: id };
  });
}

/** Avisos antes de excluir: o que depende deste registro (a tela mostra e pede confirmação). */
function avisosExcluir_(u, d) {
  defTabela_(d.tabela);
  const reg = lerTabela_(d.tabela).find(x => x._id === String(d.id || ''));
  if (!reg) return { avisos: [] };
  const av = [], conta = (tab, f) => { try { return lerTabela_(tab).filter(f).length; } catch (e) { return 0; } };
  const regs = f => { try { return lerRegistros_(f).length; } catch (e) { return 0; } };
  const q = (n, um, varios) => n + ' ' + (n === 1 ? um : varios);
  if (d.tabela === 'TIPOS_EQ') {
    const n = conta('EQUIPAMENTOS', e => normalizar_(e['Tipo']) === normalizar_(reg['Tipo de equipamento']));
    if (n) av.push(q(n, 'aparelho usa', 'aparelhos usam') + ' este tipo. Eles continuam cadastrados, mas o PMOC deles passa a usar o checklist "Split".');
  }
  if (d.tabela === 'CHECKLIST') {
    const n = regs(r => r['Checklist'] === reg['Checklist'] && r['Item'] === reg['Item']);
    if (n) av.push('Este item já foi marcado ' + q(n, 'vez', 'vezes') + ' em visitas. O histórico fica guardado, mas o item some dos próximos checklists.');
    const resto = conta('CHECKLIST', x => x['Checklist'] === reg['Checklist']) - 1;
    const tipos = conta('TIPOS_EQ', t => t['Checklist PMOC'] === reg['Checklist']);
    if (resto === 0 && tipos) av.push('É o último item do checklist "' + reg['Checklist'] + '", usado por ' + q(tipos, 'tipo', 'tipos') + ' de equipamento: o checklist ficará vazio.');
    av.push('Dica: para só tirar o item dos próximos checklists, é melhor mudar "Ativo?" para Não.');
  }
  if (d.tabela === 'CLAUSULAS') av.push('Os próximos contratos sairão sem esta cláusula. Os contratos já gerados não mudam. Para só esconder, mude "Ativo?" para Não.');
  if (d.tabela === 'CLIENTES') {
    const nome = reg['Nome / razão social'];
    const ct = conta('CONTRATOS', c => c['Cliente'] === nome && c['Situação'] !== 'Encerrado'), os = conta('SERVICOS', s => s['Cliente'] === nome), eq = conta('EQUIPAMENTOS', e => e['Cliente'] === nome);
    if (ct) av.push('O cliente tem ' + q(ct, 'contrato ativo', 'contratos ativos') + '.');
    if (os) av.push('O cliente tem ' + q(os, 'serviço (OS)', 'serviços (OS)') + ' no histórico.');
    if (eq) av.push('O cliente tem ' + q(eq, 'aparelho cadastrado', 'aparelhos cadastrados') + '.');
  }
  if (d.tabela === 'CONTRATOS') {
    const eq = conta('EQUIPAMENTOS', e => e['Contrato'] === reg._id), rg = regs(r => r['Contrato'] === reg._id);
    if (eq) av.push(q(eq, 'aparelho está ligado', 'aparelhos estão ligados') + ' ao PMOC deste contrato.');
    if (rg) av.push('Há ' + q(rg, 'item registrado', 'itens registrados') + ' de PMOC neste contrato (o histórico fica na planilha).');
  }
  if (d.tabela === 'EQUIPAMENTOS') {
    if (reg['Contrato']) av.push('Este aparelho está no PMOC do contrato ' + reg['Contrato'] + '.');
    const rg = regs(r => r['ID equipamento'] === reg._id); if (rg) av.push('Tem ' + q(rg, 'item', 'itens') + ' de PMOC registrados (o histórico fica na planilha).');
  }
  return { avisos: av };
}

/** "Excluir" = limpar os campos da linha. O código (ID) e as fórmulas continuam na planilha. */
function limpar_(u, d) {
  const t = defTabela_(d.tabela);
  if (!d.id) throw erroUsuario_('Nada para excluir.');
  return comTrava_(() => {
    const aba = abaDe_(t);
    const cab = cabecalho_(aba.getRange(1, 1, 1, aba.getLastColumn()).getValues()[0]);
    const ids = aba.getRange(1, cab[t.id] + 1, aba.getLastRow(), 1).getValues();
    const r = ids.findIndex((x, i) => i > 0 && String(x[0]) === String(d.id));
    if (r < 1) throw erroUsuario_('Registro não encontrado.');
    t.campos.forEach(c => {
      if ((SO_LEITURA[c.t] && !c.sistema) || cab[c.c] === undefined) return;
      aba.getRange(r + 1, cab[c.c] + 1).setValue(c.t === 'bool' ? false : '');
    });
    if (cab['Origem'] !== undefined) aba.getRange(r + 1, cab['Origem'] + 1).setValue('');
    esquecer_();
    log_('EXCLUIR', u.login, d.tabela + ' ' + d.id);
    return true;
  });
}

/* ===== Documentos.gs ===== */
/** ===================== DADOS DA EMPRESA (aba DADOS da planilha Sistema NG) =====================
 * Telefone, endereço, PIX, validade do orçamento… Troque na aba DADOS ou em "Dados da empresa" no sistema.
 */
const DADOS_PADRAO = {
  'Razão social': CFG.EMPRESA.razao, 'CNPJ': CFG.EMPRESA.cnpj, 'Telefone': CFG.EMPRESA.fone, 'E-mail': CFG.EMPRESA.email,
  'Endereço': CFG.EMPRESA.endereco, 'WhatsApp (só números, com 55)': '5534997777533', 'Validade do orçamento (dias)': 7,
  'Nome do recebedor PIX': 'NG AR CONDICIONADO', 'Cidade do PIX': 'UBERLANDIA'
};
function abaDados_() {
  return abaSistema_('DADOS', ['Campo', 'Valor', 'Para que serve', 'Vai para o site?']);
}
let _dados = null;
function dadosEmpresa_() {
  if (_dados) return _dados;
  const cache = CacheService.getScriptCache(), c = cache.get('DADOS_EMP');
  if (c) return (_dados = JSON.parse(c));
  const v = abaDados_().getDataRange().getValues(), o = {};
  v.slice(1).forEach(r => { const k = String(r[0]).trim(); if (k) o[k] = { v: r[1] instanceof Date ? Utilities.formatDate(r[1], CFG.FUSO, 'dd/MM/yyyy') : String(r[1]).trim(), site: normalizar_(r[3]) === 'SIM', ajuda: String(r[2] || '') }; });
  cache.put('DADOS_EMP', JSON.stringify(o), 300);
  return (_dados = o);
}
function emp_(campo) { const d = dadosEmpresa_()[campo]; return d && d.v !== '' ? d.v : (DADOS_PADRAO[campo] != null ? String(DADOS_PADRAO[campo]) : ''); }

function dadosLer_() {
  const v = abaDados_().getDataRange().getValues();
  return v.slice(1).filter(r => String(r[0]).trim()).map((r, i) => ({ linha: i + 2, campo: String(r[0]), valor: r[1] instanceof Date ? '' : String(r[1]), ajuda: String(r[2] || ''), site: normalizar_(r[3]) === 'SIM' }));
}
function dadosSalvar_(u, d) {
  const aba = abaDados_(), atual = dadosLer_();
  (d.itens || []).forEach(it => {
    const a = atual.find(x => x.linha === Number(it.linha));
    if (!a) return;
    let v = String(it.valor == null ? '' : it.valor).trim().slice(0, 600);
    if (/^Nome do recebedor PIX/.test(a.campo)) v = semAcento_(v).toUpperCase().slice(0, 25);
    if (/^Cidade do PIX/.test(a.campo)) v = semAcento_(v).toUpperCase().slice(0, 15);
    if (/^WhatsApp/.test(a.campo)) v = v.replace(/\D/g, '');
    if (v !== a.valor) aba.getRange(a.linha, 2).setNumberFormat('@').setValue(v);
    if (typeof it.site === 'boolean' && it.site !== a.site) aba.getRange(a.linha, 4).setValue(it.site ? 'Sim' : 'Não');
  });
  CacheService.getScriptCache().remove('DADOS_EMP'); _dados = null;
  log_('DADOS_EMPRESA', u.login, 'alterados');
  return true;
}
/** Só os campos marcados "Vai para o site? = Sim" saem para o site público. */
function dadosSite_() {
  const o = {}, d = dadosEmpresa_();
  // Trava extra: estes nunca saem para o site, mesmo se alguém marcar "Sim" por engano.
  const nunca = /PIX|Responsável técnico|Validade|Condições|Garantia|foro|rescisão|Token|senha|chave/i;
  Object.keys(d).forEach(k => { if (d[k].site && d[k].v && !nunca.test(k)) o[k] = d[k].v; });
  return o;
}
/** Instagram da aba DADOS como "@usuario" (aceita @, só o nome ou o link completo). */
function instaArroba_() { const u = String(emp_('Instagram') || '').trim().replace(/^https?:\/\/(www\.)?instagram\.com\//i, '').replace(/[/?#].*$/, '').replace(/^@/, ''); return u ? '@' + u : ''; }
function semAcento_(s) { return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, ''); }

/** ===================== PIX (QR Code "copia e cola") ===================== */
function crc16_(s) {
  let crc = 0xFFFF;
  for (let i = 0; i < s.length; i++) {
    crc ^= s.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
  }
  return ('000' + crc.toString(16).toUpperCase()).slice(-4);
}
function campoEmv_(id, v) { v = String(v); return id + ('0' + v.length).slice(-2) + v; }
function pixPayload_(valor, txid) {
  const chave = emp_('Chave PIX');
  if (!chave) throw erroUsuario_('Cadastre a chave PIX em "Dados da empresa" para gerar o QR Code.');
  const nome = semAcento_(emp_('Nome do recebedor PIX')).toUpperCase().replace(/[^A-Z0-9 ]/g, '').slice(0, 25) || 'NG AR CONDICIONADO';
  const cidade = semAcento_(emp_('Cidade do PIX')).toUpperCase().replace(/[^A-Z ]/g, '').slice(0, 15) || 'UBERLANDIA';
  const tx = String(txid || '***').replace(/[^A-Za-z0-9]/g, '').slice(0, 25) || '***';
  let p = campoEmv_('00', '01') + campoEmv_('26', campoEmv_('00', 'br.gov.bcb.pix') + campoEmv_('01', chave.trim())) +
    campoEmv_('52', '0000') + campoEmv_('53', '986') + (Number(valor) > 0 ? campoEmv_('54', Number(valor).toFixed(2)) : '') +
    campoEmv_('58', 'BR') + campoEmv_('59', nome) + campoEmv_('60', cidade) + campoEmv_('62', campoEmv_('05', tx)) + '6304';
  return p + crc16_(p);
}
function qrDataUrl_(texto, tam) { const q = qrcode(0, 'M'); q.addData(texto); q.make(); return q.createDataURL(tam || 5, 2); }
function pixGerar_(u, d) {
  const payload = pixPayload_(num_(d.valor), d.txid);
  return { payload: payload, qr: qrDataUrl_(payload, 6), nome: emp_('Nome do recebedor PIX'), chave: emp_('Chave PIX') };
}

/** ===================== VALOR POR EXTENSO (recibos) ===================== */
function extenso_(valor) {
  const U = ['', 'um', 'dois', 'três', 'quatro', 'cinco', 'seis', 'sete', 'oito', 'nove', 'dez', 'onze', 'doze', 'treze', 'quatorze', 'quinze', 'dezesseis', 'dezessete', 'dezoito', 'dezenove'];
  const D = ['', '', 'vinte', 'trinta', 'quarenta', 'cinquenta', 'sessenta', 'setenta', 'oitenta', 'noventa'];
  const C = ['', 'cento', 'duzentos', 'trezentos', 'quatrocentos', 'quinhentos', 'seiscentos', 'setecentos', 'oitocentos', 'novecentos'];
  const ate999 = n => {
    if (n === 100) return 'cem';
    const c = Math.floor(n / 100), r = n % 100, p = [];
    if (c) p.push(C[c]);
    if (r) p.push(r < 20 ? U[r] : D[Math.floor(r / 10)] + (r % 10 ? ' e ' + U[r % 10] : ''));
    return p.join(' e ');
  };
  const inteiro = n => {
    if (n === 0) return 'zero';
    const mi = Math.floor(n / 1e6), mil = Math.floor((n % 1e6) / 1000), r = n % 1000, p = [];
    if (mi) p.push(ate999(mi) + (mi === 1 ? ' milhão' : ' milhões'));
    if (mil) p.push(mil === 1 ? 'mil' : ate999(mil) + ' mil');
    if (r) p.push(ate999(r));
    if (p.length === 1) return p[0];
    const ultimo = p.pop();
    const usaE = r ? (r < 100 || r % 100 === 0) : true;
    return p.join(' ') + (usaE ? ' e ' : ' ') + ultimo;
  };
  const v = Math.round(Math.abs(num_(valor)) * 100), reais = Math.floor(v / 100), cent = v % 100;
  let t = reais ? inteiro(reais) + (reais === 1 ? ' real' : (reais % 1e6 === 0 ? ' de reais' : ' reais')) : '';
  if (cent) t += (t ? ' e ' : '') + inteiro(cent) + (cent === 1 ? ' centavo' : ' centavos');
  return t || 'zero real';
}

/** ===================== BASE DOS DOCUMENTOS EM PDF ===================== */
const h_ = t => String(t == null ? '' : t).replace(/[&<>"]/g, x => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[x]));
const brl_ = v => (num_(v) < 0 ? '-' : '') + 'R$ ' + Math.abs(num_(v)).toFixed(2).replace('.', ',').replace(/\B(?=(\d{3})+(?!\d))/g, '.');
const dtBR_ = t => { const x = dataDe_(t); return x ? Utilities.formatDate(x, CFG.FUSO, 'dd/MM/yyyy') : ''; };
const urlView_ = f => 'https://drive.google.com/file/d/' + f.getId() + '/view';

/** Página com logo no topo e marca d'água grande e clarinha no fundo. */
function docHtml_(titulo, subtitulo, corpo) {
  return docPaginas_([{ titulo: titulo, subtitulo: subtitulo, corpo: corpo }]);
}
/** Vários "laudos" num arquivo só: cada página começa numa folha nova, com o logo e os dados da empresa no topo. */
function docPaginas_(paginas) {
  const e = { razao: emp_('Razão social'), cnpj: emp_('CNPJ'), fone: emp_('Telefone'), email: emp_('E-mail'), end: emp_('Endereço') };
  const site = emp_('Site') ? h_(String(emp_('Site')).replace(/^https?:\/\//, '').replace(/\/$/, '')) : '';
  const topo = '<div class="topo"><img src="' + LOGO_PNG + '"><div class="emp">' + h_(e.razao) + ' · CNPJ ' + h_(e.cnpj) + ' · ' + h_(e.fone) + ' · ' + h_(e.email) + '<br>' + h_(e.end) + (site ? ' · ' + site : '') + '</div></div>';
  return '<html><head><meta charset="utf-8"><style>' +
    'body{font-family:Arial,Helvetica,sans-serif;color:#22343c;font-size:10.5pt;margin:0}' +
    '.marca{position:absolute;top:110px;left:-115px;width:936px;z-index:-1}' +
    '.topo{border-bottom:3px solid #0aa6cd;padding-bottom:8px;margin-bottom:12px}.topo img{height:58px}' +
    '.emp{font-size:8.5pt;color:#5f717a}h1{font-size:15pt;color:#2f4656;margin:12px 0 2px}h2{font-size:12pt;color:#2f4656;margin:16px 0 6px}' +
    '.sub{color:#5f717a;font-size:9.5pt;margin-bottom:12px}' +
    'table{border-collapse:collapse;width:100%;margin-bottom:10px}td,th{padding:5px 6px;border-bottom:1px solid #d9e3e7;vertical-align:top;text-align:left}' +
    '.r{color:#5f717a;width:140px}th{color:#2f4656;font-size:9.5pt;border-bottom:2px solid #0aa6cd}.n{text-align:right;white-space:nowrap}' +
    '.desc{white-space:pre-wrap;border-left:3px solid #0aa6cd;padding:2px 0 2px 10px;font-size:10pt;margin:8px 0}' +
    '.aviso{border:2px solid #d85a30;color:#993c1d;padding:8px 12px;border-radius:6px;font-weight:bold;margin:10px 0}' +
    '.total{font-size:14pt;font-weight:bold;color:#2f4656;text-align:right;margin:6px 0}' +
    '.ass{margin-top:24px;text-align:center}.ass img{height:90px}.ass .l{border-top:1px solid #22343c;width:300px;margin:0 auto;padding-top:4px;font-size:9.5pt}' +
    '.fotos img{width:48%;margin:0 1% 8px 0;border-radius:4px}.fotos div{font-size:8.5pt;color:#5f717a}' +
    '.pix{margin-top:14px;border-top:1px dashed #9fb5bd;padding-top:10px}.pix img{width:150px;float:left;margin-right:14px}.pix .c{font-size:7.5pt;word-break:break-all;color:#5f717a}' +
    '.rod{margin-top:18px;font-size:8pt;color:#8a9aa1;text-align:center;clear:both}.quebra{page-break-before:always}' +
    '.vistos{width:100%;border:0;margin-top:26px}.vistos td{border:0;text-align:center;padding:44px 6px 0;vertical-align:bottom}.vistos div{border-top:1px solid #22343c;padding-top:4px;font-size:9pt}.vistos small{color:#5f717a}' +
    // laudo compacto: cada aparelho cabe numa folha A4
    '.lc{font-size:9pt}.lc .topo{padding-bottom:4px;margin-bottom:6px}.lc .topo img{height:44px}.lc h1{font-size:12.5pt;margin:4px 0 0}.lc .sub{margin-bottom:6px;font-size:8.5pt}' +
    '.lc h2{font-size:10pt;margin:8px 0 3px}.lc table{margin-bottom:4px}.lc td,.lc th{padding:2px 5px}.lc .t8{font-size:8pt}.lc .t8 td,.lc .t8 th{padding:1.5px 4px}' +
    '.lc .vistos{margin-top:12px}.lc .vistos td{padding-top:34px}.lc .r{width:110px}' +
    // aparelho com muitos itens: letra um pouco menor para continuar numa folha só
    '.lc.denso h2{margin:5px 0 2px;font-size:9.5pt}.lc.denso .t8{font-size:7.4pt}.lc.denso .t8 td,.lc.denso .t8 th{padding:1px 4px;line-height:1.2}.lc.denso .vistos td{padding-top:28px}' +
    '.cal th.m,.cal td.m{text-align:center;padding:2px 1px;width:27px;font-size:6.8pt}.lc.denso .cal td.m{padding:1px}.lc.denso .desc{margin:3px 0;font-size:8.5pt}</style></head><body>' +
    '<img class="marca" src="' + LOGO_MARCA_DAGUA + '">' +
    paginas.map((p, i) => '<div class="folha ' + (p.classe || '') + (i ? ' quebra' : '') + '"' + (i ? ' style="page-break-before:always;break-before:page"' : '') + '>' +
      topo + '<h1>' + h_(p.titulo) + '</h1><div class="sub">' + h_(p.subtitulo) + '</div>' + p.corpo + '</div>').join('') +
    '<div class="rod">' + h_(e.razao) + (site ? ' · ' + site : '') + (instaArroba_() ? ' · ' + h_(instaArroba_()) : '') + '<br>Documento gerado em ' + agoraTxt_() + '.</div></body></html>';
}
function salvarPdf_(pasta, nome, html) {
  const velhos = pasta.getFilesByName(nome);
  while (velhos.hasNext()) velhos.next().setTrashed(true);
  const pdf = pasta.createFile(HtmlService.createHtmlOutput(html).getAs('application/pdf').setName(nome));
  let publico = true;
  try { pdf.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (x) { publico = false; }
  return { arq: pdf, url: urlView_(pdf), publico: publico };
}
/** Sr. / Sra. / neutro, conforme o cadastro do cliente. */
function tratamento_(c) {
  const g = normalizar_(c && c.genero);
  if (g === 'MASCULINO') return { pre: 'Sr. ', prezado: 'Prezado', de: 'do' };
  if (g === 'FEMININO') return { pre: 'Sra. ', prezado: 'Prezada', de: 'da' };
  return { pre: '', prezado: 'Prezado(a)', de: 'de' };
}
/** Como chamar o cliente nas mensagens ("Sr. Aldo"). Empresa: usa o "Contato no local". */
function saudacao_(nomeCliente) {
  const c = clientesPorNome_()[nomeCliente] || {};
  const pj = normalizar_(c.pessoa).indexOf('JURID') >= 0;
  const base = c.contato && (pj || !nomeCliente) ? c.contato : (pj ? '' : nomeCliente);
  const p = String(base || '').trim().split(/\s+/)[0] || '';
  if (!p) return '';
  return tratamento_(c).pre + p.charAt(0).toUpperCase() + p.slice(1).toLowerCase();
}
/** Até "max" fotos de uma pasta (antes e depois primeiro), como imagens dentro do PDF. */
function fotosDaPasta_(pasta, max) {
  if (!pasta) return [];
  const fs = pasta.getFiles(), lista = [];
  while (fs.hasNext()) { const f = fs.next(), n = f.getName(); if (/\.(jpe?g|png|webp)$/i.test(n) && !/^assinatura/.test(n)) lista.push(f); }
  const peso = n => /^antes/.test(n) ? 0 : /^depois/.test(n) ? 1 : 2;
  return lista.sort((a, b) => peso(a.getName()) - peso(b.getName()) || a.getDateCreated() - b.getDateCreated()).slice(0, max || 6)
    .map(f => ({ rot: /^antes/.test(f.getName()) ? 'Antes' : /^depois/.test(f.getName()) ? 'Depois' : 'Foto', src: 'data:' + f.getMimeType() + ';base64,' + Utilities.base64Encode(f.getBlob().getBytes()) }));
}
const blocoFotos_ = fotos => fotos.length ? '<h2>Fotos</h2><div class="fotos">' + fotos.map(f => '<span style="display:inline-block;width:48%;margin:0 1% 8px 0"><img style="width:100%" src="' + f.src + '"><div>' + h_(f.rot) + '</div></span>').join('') + '</div>' : '';

/** ===================== COMPROVANTE DO SERVIÇO (OS) ===================== */
function contratoDoServico_(s) {
  const ct = lerTabela_('CONTRATOS');
  return (s['Contrato'] && ct.find(x => x._id === s['Contrato'])) || ct.find(x => x['Cliente'] === s['Cliente'] && x['Situação'] === 'Ativo') || null;
}
function comprovanteGerar_(u, d) {
  const s = servicoDoUsuario_(u, d.id);
  const c = clientesPorNome_()[s['Cliente']] || {};
  const pasta = pastaDe_({ reg: s, raiz: 'fotos', sub: '', desc: String(s['Cliente'] || '') }, true);
  let assin = '', quem = '', maisNova = 0;
  const fs = pasta.getFiles();
  while (fs.hasNext()) {
    const f = fs.next();
    if (/^assinatura/.test(f.getName()) && f.getDateCreated().getTime() > maisNova) {
      maisNova = f.getDateCreated().getTime();
      assin = 'data:image/png;base64,' + Utilities.base64Encode(f.getBlob().getBytes());
      quem = String(f.getDescription() || '').replace(/^.*Assinatura de\s*/, '');
    }
  }
  const mats = lerTabela_('MATERIAIS').filter(x => x['Nº OS'] === s._id);
  const ct = contratoDoServico_(s);
  const valor = s['Valor'] !== '' && s['Valor'] != null && num_(s['Valor']) > 0 ? brl_(s['Valor']) : (ct ? 'Incluído no contrato ' + ct._id + ' (' + ct['Tipo'] + ')' : '');
  const linha = (r, v) => v ? '<tr><td class="r">' + h_(r) + '</td><td>' + h_(v) + '</td></tr>' : '';
  const fotos = d.fotos ? fotosDaPasta_(pasta, 6) : [];
  const corpo = '<table>' + linha('Cliente', s['Cliente']) + linha('CPF / CNPJ', c.doc) + linha('Endereço', c.end) + linha('Contato', c.contato) +
    linha('Serviço', s['Tipo']) + linha('Técnico', s['Técnico']) + linha('Situação', s['Situação']) +
    linha('Data', dtBR_(s['Concluído em']) || dtBR_(s['Agendado para'])) + linha('Valor', valor) + '</table>' +
    (s['Descrição'] ? '<div class="desc">' + h_(s['Descrição']) + '</div>' : '') +
    (mats.length ? '<h2>Materiais utilizados</h2><table><tr><th>Item</th><th>Qtd.</th><th>Un.</th></tr>' +
      mats.map(m => '<tr><td>' + h_(m['Item']) + '</td><td>' + h_(m['Quantidade']) + '</td><td>' + h_(m['Unidade']) + '</td></tr>').join('') + '</table>' : '') +
    (emp_('Garantia do serviço') ? '<div class="sub">Garantia: ' + h_(emp_('Garantia do serviço')) + '</div>' : '') +
    '<div class="ass">' + (assin ? '<img src="' + assin + '">' : '<div style="height:70px"></div>') +
    '<div class="l">' + h_(quem || 'Assinatura do responsável no local') + '</div></div>' + blocoFotos_(fotos);
  const r = salvarPdf_(pasta, 'Comprovante ' + s._id + (d.fotos ? ' (com fotos)' : '') + '.pdf', docHtml_('Comprovante de serviço · ' + s._id, 'Emitido em ' + agoraTxt_(), corpo));
  const v = { 'Comprovante': r.url };
  if (!s['Pasta / fotos']) v['Pasta / fotos'] = pasta.getUrl();
  gravar_(u, { tabela: 'SERVICOS', id: s._id, valores: v }, true);
  log_('COMPROVANTE', u.login, s._id + (d.fotos ? ' com fotos' : ''));
  return { url: r.url, publico: r.publico, tel: String(c.tel || ''), cliente: s['Cliente'], os: s._id, fotos: fotos.length, trat: saudacao_(s['Cliente']) };
}

/** ===================== RECIBO DE PAGAMENTO RECEBIDO ===================== */
function pagadorDe_(m) {
  const vinc = String(m['Vínculo (OS, cliente, funcionário)'] || '').trim();
  const cli = clientesPorNome_();
  let os = null, nome = '';
  const idOS = (vinc.match(/OS-\d+/i) || [])[0];
  if (idOS) { os = lerTabela_('SERVICOS').find(x => x._id === idOS.toUpperCase()) || null; if (os) nome = os['Cliente']; }
  if (!nome && cli[vinc]) nome = vinc;
  return { nome: nome, cliente: cli[nome] || null, os: os };
}
function reciboGerar_(u, d) {
  const m = lerTabela_('MOVIMENTO').find(x => x._id === String(d.id));
  if (!m) throw erroUsuario_('Lançamento não encontrado.');
  if (m['Entrada ou saída'] !== 'Entrada') throw erroUsuario_('Recibo é só para entradas (dinheiro recebido).');
  if (!m['Pago?']) throw erroUsuario_('Confirme o recebimento antes de gerar o recibo.');
  const p = pagadorDe_(m);
  const nome = String(d.pagador || p.nome || '').trim();
  if (!nome) throw erroUsuario_('Informe de quem foi recebido.');
  const c = p.cliente || {};
  const t = tratamento_({ genero: c.genero });
  const doc = c.doc ? ', ' + (String(c.doc).replace(/\D/g, '').length > 11 ? 'CNPJ ' : 'CPF ') + c.doc : '';
  const ref = String(d.referente || m['Descrição'] || m['Categoria'] || '').trim();
  const dataPag = dtBR_(m['Data']) || Utilities.formatDate(new Date(), CFG.FUSO, 'dd/MM/yyyy');
  let fotos = [];
  if (d.fotos) {
    const alvoOS = p.os ? pastaDe_({ reg: p.os, raiz: 'fotos', sub: '' }, false) : null;
    const alvoMov = pastaDe_({ reg: m, raiz: 'fin', sub: 'Comprovantes e recibos' }, false);
    fotos = fotosDaPasta_(alvoMov, 4).concat(fotosDaPasta_(alvoOS, 4)).slice(0, 6);
  }
  const corpo = '<div class="total" style="text-align:left;font-size:20pt;margin:8px 0 14px">' + brl_(m['Valor']) + '</div>' +
    '<p style="font-size:11.5pt;line-height:1.6">Recebemos ' + t.de + ' ' + h_(t.pre + nome) + h_(doc) + ' a importância de <b>' + brl_(m['Valor']) + '</b> (' + h_(extenso_(m['Valor'])) + ')' +
    (ref ? ', referente a ' + h_(ref) : '') + (p.os ? ' (' + h_(p.os._id) + ')' : '') + '.</p>' +
    '<p>Data do pagamento: ' + h_(dataPag) + '</p><p>Para clareza, firmamos o presente recibo.</p>' +
    '<div class="ass"><div style="height:40px"></div><div class="l">' + h_(m['Confirmado por'] || u.nome || u.login) + ' · ' + h_(emp_('Razão social')) + '<br>Recebido por</div></div>' + blocoFotos_(fotos);
  const pasta = pastaDe_({ reg: m, raiz: 'fin', sub: 'Comprovantes e recibos', desc: 'Recibo ' + m._id }, true);
  const r = salvarPdf_(pasta, 'Recibo ' + m._id + '.pdf', docHtml_('Recibo · ' + m._id, 'Emitido em ' + agoraTxt_(), corpo));
  gravar_(u, { tabela: 'MOVIMENTO', id: m._id, valores: { 'Recibo': r.url } }, true);
  log_('RECIBO', u.login, m._id);
  return { url: r.url, publico: r.publico, tel: String(c.tel || ''), nome: nome, id: m._id, trat: saudacao_(nome) };
}

/** ===================== ORÇAMENTOS ===================== */
function orcamentoInfo_(u, d) {
  const o = d.id ? lerTabela_('ORCAMENTOS').find(x => x._id === String(d.id)) : null;
  if (d.id && !o) throw erroUsuario_('Orçamento não encontrado.');
  return {
    orc: o, itens: o ? lerTabela_('ITENS_ORC').filter(x => x['Nº orçamento'] === o._id).map(x => ({ id: x._id, servico: x['Serviço'], descricao: x['Descrição'], qtd: num_(x['Quantidade']) || 1, valor: num_(x['Valor unitário']) })) : [],
    precos: lerTabela_('PRECOS').filter(x => normalizar_(x['Ativo?']) !== 'NAO' && !exemplo_(x['Serviço'])).map(x => ({ servico: x['Serviço'], descricao: x['Descrição'], unidade: x['Unidade'], valor: num_(x['Valor']) })),
    clientes: Object.keys(clientesPorNome_()).filter(n => !exemplo_(n)).sort((a, b) => a.localeCompare(b, 'pt-BR')),
    validade: Number(emp_('Validade do orçamento (dias)')) || 7, pix: !!emp_('Chave PIX')
  };
}
function orcamentoSalvar_(u, d) {
  const v = d.valores || {};
  if (!v['Cliente']) throw erroUsuario_('Escolha o cliente.');
  const itens = (d.itens || []).filter(i => String(i.servico || '').trim()).slice(0, 60);
  if (!itens.length) throw erroUsuario_('Coloque pelo menos um serviço no orçamento.');
  const val = { 'Cliente': v['Cliente'], 'Data': v['Data'] || fmtData_(hoje_()), 'Validade (dias)': Number(v['Validade (dias)']) || Number(emp_('Validade do orçamento (dias)')) || 7,
    'Situação': v['Situação'] || 'Aberto', 'Desconto': num_(v['Desconto']) || '', 'Observações': String(v['Observações'] || ''),
    'Tipo': ['Serviço avulso', 'Contrato mensal', 'Contrato PMOC', 'Contrato anual'].indexOf(v['Tipo']) >= 0 ? v['Tipo'] : 'Serviço avulso' };
  if (!d.id) val['Feito por'] = u.nome || u.login;
  const r = gravar_(u, { tabela: 'ORCAMENTOS', id: d.id || '', valores: val }, true);
  const id = r.id;
  comTrava_(() => {
    const aba = abaDe_(defTabela_('ITENS_ORC'));
    const vals = aba.getRange(1, 1, aba.getLastRow(), 6).getValues(), cab = cabecalho_(vals[0]);
    const cO = cab['Nº orçamento'], cS = cab['Serviço'];
    const livres = [];
    for (let i = 1; i < vals.length; i++) {
      if (String(vals[i][cO]) === id) { aba.getRange(i + 1, 2, 1, 5).clearContent(); livres.push(i + 1); }
      else if (!String(vals[i][cS]).trim() && String(vals[i][0]).trim()) livres.push(i + 1);
    }
    livres.sort((a, b) => a - b);
    if (livres.length < itens.length) throw erroUsuario_('A aba ITENS DO ORÇAMENTO está cheia. Acrescente linhas com ID na planilha.');
    itens.forEach((it, k) => aba.getRange(livres[k], 2, 1, 5).setValues([[id, String(it.servico).slice(0, 200), String(it.descricao || '').slice(0, 300), num_(it.qtd) || 1, num_(it.valor)]]));
    esquecer_('ITENS_ORC');
  });
  log_(d.id ? 'ORCAMENTO_EDITADO' : 'ORCAMENTO_CRIADO', u.login, id);
  return { id: id };
}
function orcamentoPdf_(u, d) {
  const info = orcamentoInfo_(u, { id: d.id }), o = info.orc;
  const c = clientesPorNome_()[o['Cliente']] || {};
  const t = tratamento_({ genero: c.genero });
  const sub = info.itens.reduce((s, i) => s + i.qtd * i.valor, 0), desc = num_(o['Desconto']), total = sub - desc;
  const dias = Number(o['Validade (dias)']) || 7;
  const ate = dataDe_(o['Data']) ? new Date(dataDe_(o['Data']).getTime() + dias * 864e5) : new Date(Date.now() + dias * 864e5);
  let pix = '';
  if (d.pix && emp_('Chave PIX') && total > 0) {
    const pl = pixPayload_(total, o._id);
    pix = '<div class="pix"><img src="' + qrDataUrl_(pl, 5) + '"><b>Pague com PIX</b><br>' + h_(emp_('Nome do recebedor PIX')) + ' · chave ' + h_(emp_('Chave PIX')) + '<br>Valor: ' + brl_(total) +
      '<div class="c">PIX copia e cola: ' + h_(pl) + '</div></div>';
  }
  const corpo = '<p>' + t.prezado + ' ' + h_(t.pre + o['Cliente']) + ',<br>segue o orçamento solicitado.</p>' +
    '<div class="aviso">Este orçamento é válido até ' + Utilities.formatDate(ate, CFG.FUSO, 'dd/MM/yyyy') + ' (' + dias + ' dias). Depois dessa data, os valores e a disponibilidade de agenda podem mudar.</div>' +
    '<table><tr><th>Serviço</th><th class="n">Qtd.</th><th class="n">Valor unit.</th><th class="n">Total</th></tr>' +
    info.itens.map(i => '<tr><td><b>' + h_(i.servico) + '</b>' + (i.descricao ? '<br><span style="color:#5f717a;font-size:9pt">' + h_(i.descricao) + '</span>' : '') + '</td><td class="n">' + h_(String(i.qtd).replace('.', ',')) + '</td><td class="n">' + brl_(i.valor) + '</td><td class="n">' + brl_(i.qtd * i.valor) + '</td></tr>').join('') + '</table>' +
    (desc ? '<div style="text-align:right">Subtotal ' + brl_(sub) + ' · Desconto ' + brl_(desc) + '</div>' : '') + '<div class="total">' + (/mensal|PMOC/i.test(o['Tipo'] || '') ? 'Valor mensal: ' : /anual/i.test(o['Tipo'] || '') ? 'Valor anual: ' : 'Total: ') + brl_(total) + '</div>' +
    (o['Observações'] ? '<div class="desc">' + h_(o['Observações']) + '</div>' : '') +
    (emp_('Formas de pagamento aceitas') ? '<div class="sub"><b>Formas de pagamento:</b> ' + h_(emp_('Formas de pagamento aceitas')) + '</div>' : '') +
    (emp_('Condições do orçamento') ? '<div class="sub">' + h_(emp_('Condições do orçamento')) + '</div>' : '') +
    (emp_('Garantia do serviço') ? '<div class="sub">Garantia: ' + h_(emp_('Garantia do serviço')) + '</div>' : '') +
    '<div class="sub">Responsável: ' + h_(o['Feito por'] || u.nome || u.login) + ' · ' + h_(emp_('Telefone')) + '</div>' + pix;
  const pasta = subpasta_(pastaRaiz_('docs'), 'Orçamentos', true);
  const r = salvarPdf_(pasta, 'Orçamento ' + o._id + ' · ' + String(o['Cliente']).replace(/[\\/:*?"<>|]/g, '') + '.pdf', docHtml_('Orçamento ' + o._id, 'Emitido em ' + agoraTxt_(), corpo));
  const v = { 'PDF': r.url };
  if (o['Situação'] === 'Aberto') v['Situação'] = 'Enviado';
  gravar_(u, { tabela: 'ORCAMENTOS', id: o._id, valores: v }, true);
  log_('ORCAMENTO_PDF', u.login, o._id);
  return { url: r.url, publico: r.publico, tel: String(c.tel || ''), cliente: o['Cliente'], id: o._id, total: total, ate: Utilities.formatDate(ate, CFG.FUSO, 'dd/MM/yyyy'), trat: saudacao_(o['Cliente']) };
}
/** ===================== FECHAR NEGÓCIO (orçamento aprovado) =====================
 * Um passo só: o cliente aprovou o orçamento e o sistema cria, conforme o tipo:
 *  - Serviço avulso: a OS + o lançamento "a receber" (ou já recebido, com recibo)
 *  - Contrato: o contrato com os itens do orçamento (PDF para assinar) + a OS da primeira visita + a 1ª mensalidade
 */
const TIPO_CONTRATO = { 'Contrato mensal': 'Mensal', 'Contrato PMOC': 'PMOC', 'Contrato anual': 'Anual' };
function orcamentoAprovar_(u, d) { return fecharNegocio_(u, Object.assign({ os: { abrir: true } }, d)); }
function fecharNegocio_(u, d) {
  const info = orcamentoInfo_(u, { id: d.id }), o = info.orc;
  if (o['Situação'] === 'Aprovado' && (o['OS gerada'] || o['Contrato gerado'])) throw erroUsuario_('Este orçamento já foi fechado (' + [o['OS gerada'], o['Contrato gerado']].filter(Boolean).join(', ') + ').');
  if (!info.itens.length) throw erroUsuario_('O orçamento não tem serviços.');
  const total = Math.round((info.itens.reduce((s, i) => s + i.qtd * i.valor, 0) - num_(o['Desconto'])) * 100) / 100;
  const tipoOrc = o['Tipo'] || 'Serviço avulso', ehContrato = !!TIPO_CONTRATO[tipoOrc];
  const lista = info.itens.map(i => '- ' + String(i.qtd).replace('.', ',') + ' × ' + i.servico + (i.descricao ? ' (' + i.descricao + ')' : '')).join('\n');
  const tipos = listaLISTAS_('Tipos de serviço');
  const tipoServ = (ehContrato && tipoOrc === 'Contrato PMOC' && tipos.indexOf('PMOC') >= 0) ? 'PMOC'
    : (tipos.find(t => info.itens.some(i => normalizar_(i.servico).indexOf(normalizar_(t)) >= 0)) || (ehContrato ? 'Manutenção preventiva' : ''));
  const out = { cliente: o['Cliente'], tel: String((clientesPorNome_()[o['Cliente']] || {}).tel || ''), orcamento: o._id, total: total, tipo: tipoOrc, trat: saudacao_(o['Cliente']) };
  const vinc = [o._id];
  // 1) Contrato
  if (ehContrato && (!d.contrato || d.contrato.gerar !== false)) {
    const c = d.contrato || {};
    const ini = dataDe_(c.inicio) || hoje_(), meses = Math.max(0, Math.min(120, Number(c.meses) || 12));
    const fim = meses ? new Date(ini.getFullYear(), ini.getMonth() + meses, ini.getDate() - 1) : null;
    const rc = gravar_(u, { tabela: 'CONTRATOS', id: '', valores: { 'Cliente': o['Cliente'], 'Tipo': TIPO_CONTRATO[tipoOrc], 'Serviços incluídos': info.itens.map(i => i.servico + (i.qtd !== 1 ? ' (' + String(i.qtd).replace('.', ',') + ')' : '')).join('; '),
      'Valor': total, 'Forma de pagamento': ['PIX', 'Boleto', 'Cartão', 'Dinheiro', 'Transferência'].indexOf(d.forma) >= 0 ? d.forma : '', 'Início': fmtData_(ini), 'Fim': fim ? fmtData_(fim) : '', 'Dia de vencimento': Number(c.dia) || ini.getDate(), 'Situação': 'Ativo', 'Orçamento': o._id,
      'Observações': o['Observações'] || '' } }, true);
    out.contrato = { id: rc.id };
    try { const doc = contratoGerar_(u, { id: rc.id }); out.contrato.url = doc.url; } catch (e) { out.contrato.erro = e.message; }
    vinc.push(rc.id);
  }
  // 2) Ordem de serviço
  if (d.os && d.os.abrir) {
    const ag = dataDe_(d.os.data);
    const rs = gravar_(u, { tabela: 'SERVICOS', id: '', valores: { 'Cliente': o['Cliente'], 'Tipo': tipoServ, 'Aberto em': fmtData_(hoje_()), 'Agendado para': ag ? fmtData_(ag) : '',
      'Técnico': String(d.os.tecnico || ''), 'Situação': ag ? 'Agendado' : 'Aprovado', 'Valor': ehContrato ? '' : total, 'Contrato': out.contrato ? out.contrato.id : '',
      'Descrição': (ehContrato ? 'Primeira visita do contrato ' + out.contrato.id + ' (orçamento ' + o._id + '):\n' : 'Orçamento ' + o._id + ' aprovado:\n') + lista } }, true);
    out.os = rs.id; vinc.push(rs.id);
  }
  // 3) Financeiro: a receber e, se já pagou, o recebimento com recibo
  if (tem_(u, 'financeiro') && d.cobrar && d.cobrar.lancar !== false) {
    const rec = d.recebido && d.recebido.sim ? Math.min(total, num_(d.recebido.valor) || total) : 0;
    const quando = dataDe_(d.cobrar.data) || hoje_();
    const desc = (ehContrato ? '1ª mensalidade · ' + (out.contrato ? out.contrato.id : '') : 'Serviço · ' + (out.os || o._id)) + ' · ' + o['Cliente'];
    const forma = ['PIX', 'Boleto', 'Cartão', 'Dinheiro', 'Transferência'].indexOf(d.forma) >= 0 ? d.forma : '';
    out.forma = forma;
    const base = { 'Entrada ou saída': 'Entrada', 'Categoria': ehContrato ? 'Contrato' : 'Serviço', 'Vínculo (OS, cliente, funcionário)': vinc.concat([o['Cliente']]).join(' · '), 'Forma de pagamento': forma };
    if (rec > 0) {
      const rr = gravar_(u, { tabela: 'MOVIMENTO', id: '', valores: Object.assign({}, base, { 'Data': fmtData_(hoje_()), 'Descrição': desc + (rec < total ? ' (sinal)' : ''), 'Valor': rec, 'Pago?': true,
        'Confirmado por': u.nome || u.login, 'Confirmado em': agoraTxt_() }) }, true);
      out.recebido = { id: rr.id, valor: rec };
      try { const rb = reciboGerar_(u, { id: rr.id, pagador: o['Cliente'], referente: desc }); out.recebido.url = rb.url; } catch (e) { out.recebido.erro = e.message; }
    }
    if (total - rec > 0.004) {
      const ra = gravar_(u, { tabela: 'MOVIMENTO', id: '', valores: Object.assign({}, base, { 'Data': fmtData_(quando), 'Descrição': desc + (rec ? ' (restante)' : ''), 'Valor': Math.round((total - rec) * 100) / 100, 'Pago?': false }) }, true);
      out.aReceber = { id: ra.id, valor: Math.round((total - rec) * 100) / 100, data: fmtData_(quando) };
    }
  }
  gravar_(u, { tabela: 'ORCAMENTOS', id: o._id, valores: { 'Situação': 'Aprovado', 'OS gerada': out.os || '', 'Contrato gerado': out.contrato ? out.contrato.id : '',
    'Lançamento': [out.recebido && out.recebido.id, out.aReceber && out.aReceber.id].filter(Boolean).join(' · ') } }, true);
  if (out.contrato && (d.equipamentos || []).length) { try { out.pmoc = pmocVincular_(u, { id: out.contrato.id, equipamentos: d.equipamentos }); } catch (e) { out.avisoPmoc = e.message; } }
  log_('NEGOCIO_FECHADO', u.login, o._id + ' -> ' + vinc.slice(1).join(', '));
  return out;
}

/** ===================== CONTRATO (documento para imprimir e assinar) =====================
 * As cláusulas ficam na planilha Sistema NG, aba CLÁUSULAS DO CONTRATO (veja Clausulas.gs).
 * Importante: é um modelo. Peça para um advogado revisar antes de usar com clientes.
 */
const PERIODO_CONTRATO = { 'Mensal': 'mensal', 'Trimestral': 'trimestral', 'Semestral': 'semestral', 'Anual': 'anual', 'PMOC': 'mensal' };
function contratoGerar_(u, d) {
  const ct = lerTabela_('CONTRATOS').find(x => x._id === String(d.id));
  if (!ct) throw erroUsuario_('Contrato não encontrado.');
  const c = clientesPorNome_()[ct['Cliente']] || {}, t = tratamento_(c);
  const pj = normalizar_(c.pessoa) === 'JURIDICA' || String(c.doc || '').replace(/\D/g, '').length === 14;
  const fem = normalizar_(c.genero) === 'FEMININO';
  const contratante = pj
    ? '<b>' + h_(ct['Cliente']) + '</b>, pessoa jurídica inscrita no CNPJ nº ' + h_(c.doc || '________________') + ', com sede em ' + h_(c.end || '________________') + ', doravante denominada <b>CONTRATANTE</b>'
    : '<b>' + h_(t.pre + ct['Cliente']) + '</b>, inscrit' + (fem ? 'a' : 'o') + ' no CPF nº ' + h_(c.doc || '________________') + ', residente em ' + h_(c.end || '________________') + ', doravante denominad' + (fem ? 'a' : 'o') + ' <b>CONTRATANTE</b>';
  const contratada = '<b>' + h_(emp_('Razão social')) + '</b>, inscrita no CNPJ nº ' + h_(emp_('CNPJ')) + ', com sede em ' + h_(emp_('Endereço')) + ', doravante denominada <b>CONTRATADA</b>';
  // Itens do orçamento ligado ao contrato (se houver)
  let itens = [];
  if (ct['Orçamento']) itens = lerTabela_('ITENS_ORC').filter(x => x['Nº orçamento'] === ct['Orçamento']).map(x => ({ servico: x['Serviço'], descricao: x['Descrição'], qtd: num_(x['Quantidade']) || 1, valor: num_(x['Valor unitário']) }));
  const orc = ct['Orçamento'] ? lerTabela_('ORCAMENTOS').find(x => x._id === ct['Orçamento']) : null;
  const tabItens = itens.length ? '<table><tr><th>Serviço</th><th class="n">Qtd.</th><th class="n">Valor unit.</th><th class="n">Total</th></tr>' +
    itens.map(i => '<tr><td><b>' + h_(i.servico) + '</b>' + (i.descricao ? '<br><span style="color:#5f717a;font-size:9pt">' + h_(i.descricao) + '</span>' : '') + '</td><td class="n">' + String(i.qtd).replace('.', ',') + '</td><td class="n">' + brl_(i.valor) + '</td><td class="n">' + brl_(i.qtd * i.valor) + '</td></tr>').join('') +
    (orc && num_(orc['Desconto']) ? '<tr><td colspan="3" class="n">Desconto</td><td class="n">-' + brl_(orc['Desconto']) + '</td></tr>' : '') + '</table>' : '';
  const unico = /UNICO/.test(normalizar_(ct['Tipo']));
  const periodo = PERIODO_CONTRATO[ct['Tipo']] || 'mensal';
  const valor = num_(ct['Valor']);
  const aviso = emp_('Aviso de rescisão (dias)') || '30', foro = emp_('Cidade do foro (contratos)') || 'Uberlândia/MG';
  const rt = emp_('Responsável técnico');
  const pmoc = /PMOC/.test(normalizar_(ct['Tipo'] + ' ' + ct['Serviços incluídos']));
  const forma = ct['Forma de pagamento'] ? ', por ' + h_(String(ct['Forma de pagamento']).toLowerCase() === 'boleto' ? 'boleto bancário' : String(ct['Forma de pagamento']).toLowerCase()) : '';
  const vazio = '<span style="color:#9fb5bd">__________</span>';
  const campos = {
    VALOR: '<b>' + brl_(valor) + '</b>', VALOR_EXTENSO: h_(extenso_(valor)), PERIODO: h_(periodo), DIA_VENCIMENTO: h_(ct['Dia de vencimento'] || '___'), FORMA: forma,
    INICIO: h_(dtBR_(ct['Início']) || '___/___/____'), FIM: ct['Fim'] ? h_(dtBR_(ct['Fim'])) : 'prazo indeterminado', ATE: ct['Fim'] ? 'até ' + h_(dtBR_(ct['Fim'])) : 'por prazo indeterminado',
    AVISO_DIAS: h_(aviso), FORO: h_(foro), GARANTIA: h_(String(emp_('Garantia do serviço') || '90 (noventa) dias').replace(/\.\s*$/, '')),
    RESPONSAVEL_TECNICO: rt ? h_(rt) : vazio, REGISTRO_RT: emp_('Registro do responsável técnico') ? h_(emp_('Registro do responsável técnico')) : 'registro ' + vazio,
    ART: ct['ART / TRT'] ? h_(ct['ART / TRT']) : vazio, ORCAMENTO: ct['Orçamento'] ? ', conforme o orçamento ' + h_(ct['Orçamento']) : ''
  };
  const servicos = (ct['Serviços incluídos'] ? '<div class="desc">' + h_(ct['Serviços incluídos']) + '</div>' : '') + tabItens;
  const corpo =
    '<p style="text-align:justify">Pelo presente instrumento particular, de um lado ' + contratada + ', e de outro ' + contratante + ', têm entre si justo e contratado o seguinte:</p>' +
    clausulasHtml_(ct['Tipo'], unico, pmoc, campos, servicos) +
    (ct['Observações'] ? '<h2>Observações</h2><div class="desc">' + h_(ct['Observações']) + '</div>' : '') +
    '<p style="margin-top:18px">' + h_(foro.split('/')[0]) + ', ' + Utilities.formatDate(new Date(), CFG.FUSO, "dd 'de' MMMM 'de' yyyy").replace(/January|February|March|April|May|June|July|August|September|October|November|December/, m => ({ January: 'janeiro', February: 'fevereiro', March: 'março', April: 'abril', May: 'maio', June: 'junho', July: 'julho', August: 'agosto', September: 'setembro', October: 'outubro', November: 'novembro', December: 'dezembro' }[m])) + '.</p>' +
    '<table style="margin-top:40px;border:0"><tr><td style="border:0;width:50%;text-align:center;padding-top:30px"><div style="border-top:1px solid #22343c;margin:0 16px;padding-top:4px">' + h_(emp_('Razão social')) + '<br><small>CONTRATADA</small></div></td>' +
    '<td style="border:0;width:50%;text-align:center;padding-top:30px"><div style="border-top:1px solid #22343c;margin:0 16px;padding-top:4px">' + h_(ct['Cliente']) + '<br><small>CONTRATANTE</small></div></td></tr>' +
    '<tr><td style="border:0;text-align:center;padding-top:40px"><div style="border-top:1px solid #22343c;margin:0 16px;padding-top:4px">Testemunha 1<br><small>Nome e CPF</small></div></td>' +
    '<td style="border:0;text-align:center;padding-top:40px"><div style="border-top:1px solid #22343c;margin:0 16px;padding-top:4px">Testemunha 2<br><small>Nome e CPF</small></div></td></tr></table>';
  const pasta = pastaDe_({ reg: ct, raiz: 'docs', sub: 'Contratos', desc: ct['Cliente'] + ' · ' + ct['Tipo'] }, true);
  const r = salvarPdf_(pasta, 'Contrato ' + ct._id + ' - ' + String(ct['Cliente']).slice(0, 60) + '.pdf', docHtml_('Contrato de prestação de serviços · ' + ct._id, ct['Tipo'] + ' · ' + ct['Cliente'], corpo));
  const v = { 'Documento': r.url };
  if (!ct['Arquivos']) v['Arquivos'] = pasta.getUrl();
  gravar_(u, { tabela: 'CONTRATOS', id: ct._id, valores: v }, true);
  log_('CONTRATO_GERADO', u.login, ct._id);
  return { url: r.url, id: r.arq.getId(), tel: String(c.tel || ''), cliente: ct['Cliente'], trat: saudacao_(ct['Cliente']) };
}

/** ===================== BOLETO =====================
 * O boleto é emitido no site/app do banco. Aqui o sistema guarda o PDF e a linha digitável
 * junto do lançamento e ajuda a enviar para o cliente. */
function boletoSalvar_(u, d) {
  const m = lerTabela_('MOVIMENTO').find(x => x._id === String(d.id));
  if (!m) throw erroUsuario_('Lançamento não encontrado.');
  const v = { 'Forma de pagamento': 'Boleto' };
  if (d.linha !== undefined) v['Linha digitável'] = String(d.linha || '').replace(/[^\d .]/g, '').trim().slice(0, 80);
  let url = m['Boleto'];
  if (d.base64) {
    const mime = d.mime === 'application/pdf' ? 'application/pdf' : 'image/jpeg';
    const bytes = Utilities.base64Decode(String(d.base64).replace(/^data:[^,]+,/, ''));
    if (bytes.length > CFG.FOTO_MAX_MB * 1048576) throw erroUsuario_('Arquivo grande demais.');
    const pasta = pastaDe_({ reg: m, raiz: 'fin', sub: 'Comprovantes e recibos', desc: 'Boleto ' + m._id }, true);
    const velhos = pasta.getFilesByName('Boleto ' + m._id + EXT[mime]); while (velhos.hasNext()) velhos.next().setTrashed(true);
    const arq = pasta.createFile(Utilities.newBlob(bytes, mime, 'Boleto ' + m._id + EXT[mime]));
    try { arq.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (e) { }
    url = 'https://drive.google.com/file/d/' + arq.getId() + '/view';
    v['Boleto'] = url;
  }
  gravar_(u, { tabela: 'MOVIMENTO', id: m._id, valores: v }, true);
  const p = pagadorDe_(m);
  log_('BOLETO', u.login, m._id);
  return { url: url || '', linha: v['Linha digitável'] !== undefined ? v['Linha digitável'] : m['Linha digitável'], tel: String((p.cliente || {}).tel || ''), nome: p.nome || '', valor: num_(m['Valor']), venc: m['Data'], trat: saudacao_(p.nome || '') };
}

/** ===================== FICHA DO CLIENTE (tudo num lugar só) ===================== */
function clienteResumo_(u, d) {
  const nome = String(d.nome || '');
  const out = { orcamentos: [], contratos: [], servicos: [], financeiro: [] };
  if (tem_(u, 'orcamentos')) out.orcamentos = lerTabela_('ORCAMENTOS').filter(x => x['Cliente'] === nome).map(x => ({ id: x._id, data: x['Data'], tipo: x['Tipo'], situacao: x['Situação'], alerta: x['Alerta'], total: x['Total'], pdf: x['PDF'] })).reverse();
  out.contratos = lerTabela_('CONTRATOS').filter(x => x['Cliente'] === nome).map(x => ({ id: x._id, tipo: x['Tipo'], situacao: x['Situação'], alerta: x['Alerta'], valor: x['Valor'], fim: x['Fim'], doc: x['Documento'], plano: x['Plano PMOC'] }));
  out.equipamentos = lerTabela_('EQUIPAMENTOS').filter(x => x['Cliente'] === nome).map(x => ({ id: x._id, local: x['Local / setor'], tipo: x['Tipo'], marca: x['Marca'], cap: x['Capacidade'], contrato: x['Contrato'] }));
  if (tem_(u, 'servicos')) out.servicos = lerTabela_('SERVICOS').filter(x => x['Cliente'] === nome).map(x => ({ id: x._id, tipo: x['Tipo'], data: x['Agendado para'] || x['Aberto em'], situacao: x['Situação'], comp: x['Comprovante'] })).reverse().slice(0, 30);
  if (tem_(u, 'financeiro')) out.financeiro = lerTabela_('MOVIMENTO').filter(x => String(x['Vínculo (OS, cliente, funcionário)'] || '').indexOf(nome) >= 0 && x['Entrada ou saída'] === 'Entrada')
    .map(x => ({ id: x._id, data: x['Data'], desc: x['Descrição'], valor: x['Valor'], pago: !!x['Pago?'], recibo: x['Recibo'] })).reverse().slice(0, 30);
  return out;
}

/** ===================== VER UM ARQUIVO SEM SAIR DO SISTEMA ===================== */
function arquivoVer_(u, d) {
  const f = DriveApp.getFileById(String(d.id || ''));
  const raizes = { [idDe_('PASTA_FOTOS')]: ['agenda', 'servicos', 'equipamentos'], [idDe_('PASTA_DOCS')]: ['clientes', 'orcamentos', 'servicos'] };
  try { raizes[pastaRaiz_('fin').getId()] = ['financeiro', 'fixas', 'reserva']; } catch (e) { }
  let pode = false, nivel = [f], passos = 0;
  while (nivel.length && passos < 6 && !pode) {
    const prox = [];
    nivel.forEach(x => { const ps = x.getParents(); while (ps.hasNext()) { const p = ps.next(), mods = raizes[p.getId()]; if (mods) { if (mods.some(m => tem_(u, m))) pode = true; } else prox.push(p); } });
    nivel = prox; passos++;
  }
  if (!pode) throw erroUsuario_('Você não tem acesso a este arquivo.');
  const mime = f.getMimeType(), tam = f.getSize();
  const img = /^image\//.test(mime) && tam < 6 * 1048576;
  return { nome: f.getName(), mime: mime, url: urlView_(f), dados: img ? 'data:' + mime + ';base64,' + Utilities.base64Encode(f.getBlob().getBytes()) : '' };
}

/** ===================== FUNCIONÁRIO + ACESSO AO SISTEMA (tudo num lugar só) ===================== */
function acessoFuncionario_(u, d) {
  const lista = usuariosListar_();
  const usuario = lista.usuarios.find(x => x.funcionario && x.funcionario === d.funcionario) || null;
  return { usuario: usuario, perfis: lista.perfis, modulos: lista.modulos, logins: lista.usuarios.map(x => x.login) };
}

/** ===================== INSTAGRAM NO MURAL DO SITE =====================
 * Precisa de conta profissional (comercial ou criador de conteúdo) e de um token
 * da "API do Instagram com login do Instagram". Cole o token na aba DADOS, linha "Token do Instagram".
 * O sistema guarda as fotos por 1 hora e renova o token sozinho (ele vale 60 dias e é renovado a cada ~20).
 */
function instaFotos_() {
  const cache = CacheService.getScriptCache();
  const guardado = cache.get('INSTA_FOTOS');
  if (guardado) return JSON.parse(guardado);
  const token = String(emp_('Token do Instagram') || '').trim();
  if (!token) return { fotos: [] };
  const campos = 'id,caption,media_type,media_url,thumbnail_url,permalink,timestamp';
  const resp = UrlFetchApp.fetch('https://graph.instagram.com/me/media?fields=' + campos + '&limit=12&access_token=' + encodeURIComponent(token), { muteHttpExceptions: true });
  if (resp.getResponseCode() !== 200) { log_('INSTA_ERRO', 'site', String(resp.getContentText()).slice(0, 200)); return { fotos: [], erro: true }; }
  const lista = (JSON.parse(resp.getContentText()).data || []).map(m => ({
    src: m.media_type === 'VIDEO' ? m.thumbnail_url : m.media_url, link: m.permalink, video: m.media_type === 'VIDEO',
    legenda: String(m.caption || '').split('\n')[0].slice(0, 90) })).filter(f => f.src).slice(0, 9);
  const out = { fotos: lista };
  cache.put('INSTA_FOTOS', JSON.stringify(out), 3600);
  renovarTokenInsta_(token);
  return out;
}
function renovarTokenInsta_(token) {
  const pr = PropertiesService.getScriptProperties(), ult = Number(pr.getProperty('INSTA_RENOVADO') || 0);
  if (Date.now() - ult < 20 * 86400000) return;
  try {
    const r = UrlFetchApp.fetch('https://graph.instagram.com/refresh_access_token?grant_type=ig_refresh_token&access_token=' + encodeURIComponent(token), { muteHttpExceptions: true });
    if (r.getResponseCode() !== 200) return;
    const novo = JSON.parse(r.getContentText()).access_token;
    if (novo && novo !== token) {
      const aba = abaDados_(), v = aba.getDataRange().getValues();
      for (let i = 1; i < v.length; i++) if (String(v[i][0]).trim() === 'Token do Instagram') { aba.getRange(i + 1, 2).setValue(novo); break; }
      CacheService.getScriptCache().remove('DADOS_EMP'); _dados = null;
    }
    pr.setProperty('INSTA_RENOVADO', String(Date.now()));
  } catch (e) { }
}

/* ===== Instalacao.gs ===== */
/** ===================== INSTALAÇÃO (planilhas e pastas) =====================
 * O sistema usa 4 planilhas e 2 pastas. Os IDs ficam em CFG.IDS (Config.gs).
 * Ao rodar configuracaoInicial, se alguma planilha ou pasta NÃO puder ser aberta (outra conta, apagada, ID errado),
 * o sistema cria uma nova na pasta "Sistema NG - dados" (ao lado do projeto do Apps Script) e passa a usar a nova.
 * Os IDs novos ficam guardados nas propriedades do script (não precisa mexer no Config.gs).
 *
 * Limite: as planilhas criadas assim têm todas as abas, colunas, listas e checklists, e as contas principais
 * (totais do orçamento, total dos itens e materiais, pago no ano, saldo da reserva). Os painéis e alertas coloridos
 * das planilhas originais não são recriados. Para ter tudo igual, o melhor é fazer uma cópia das planilhas originais
 * (Arquivo > Fazer uma cópia) e colocar os IDs no Config.gs.
 */
const NOMES_PLANILHAS = { SISTEMA: 'Sistema NG', OPERACAO: 'Operação NG', EQUIPE: 'Equipe NG', FINANCEIRO: 'Financeiro NG' };
const NOMES_PASTAS = { PASTA_DOCS: 'Documentos (orçamentos, contratos, PMOC)', PASTA_FOTOS: 'Fotos dos serviços' };
// prefixo do código, nº de dígitos e quantas linhas já vêm com código
const ESTRUTURA_IDS = {
  SERVICOS: ['OS-', 4, 1000], CLIENTES: ['CLI-', 4, 500], CONTRATOS: ['CTR-', 4, 200], ORCAMENTOS: ['ORC-', 4, 500], ITENS_ORC: ['IT-', 5, 2000],
  PRECOS: ['PRC-', 3, 100], EQUIPAMENTOS: ['EQP-', 4, 1000], CHECKLIST: ['CHK-', 4, 600], TIPOS_EQ: ['TIP-', 3, 100], PMOC: ['PMC-', 4, 1000],
  ESTOQUE: ['MAT-', 3, 300], MATERIAIS: ['MU-', 5, 1000], MOVIMENTO: ['MOV-', 5, 3000], FIXAS: ['FIX-', 3, 60], RESERVA: ['RES-', 4, 500],
  FUNCIONARIOS: ['FUN-', 3, 100], PRESENCA: ['PR-', 5, 3000], PONTO: ['PT-', 5, 5000]
};
const LISTAS_PADRAO = {
  'Técnicos': ['Técnico 1'],
  'Tipos de serviço': ['Instalação', 'Manutenção preventiva', 'Manutenção corretiva', 'PMOC', 'Higienização', 'Visita / orçamento', 'Desinstalação', 'Outros'],
  'Situação do serviço': ['Orçamento', 'Aprovado', 'Agendado', 'Em andamento', 'Concluído', 'Cancelado'],
  'Tipos de equipamento': null, // fórmula: puxa da aba TIPOS DE EQUIPAMENTO
  'Frequência': ['Mensal', 'Bimestral', 'Trimestral', 'Semestral', 'Anual'], 'Meses da frequência': [1, 2, 3, 6, 12],
  'Tipo de cliente': ['Residencial', 'Empresa', 'Contrato PMOC', 'Órgão público'],
  'Categorias de estoque': ['Gás refrigerante', 'Tubulação e isolamento', 'Elétrica', 'Peças e componentes', 'Outros'],
  'Tipos de contrato': ['Mensal', 'PMOC', 'Anual', 'Único (avulso)'], 'Gênero': ['Masculino', 'Feminino', 'Empresa / neutro'], 'Pessoa': ['Física', 'Jurídica']
};

let _ids = null;
/** ID de uma planilha ou pasta: o criado pela instalação (propriedades do script) ou o do Config.gs. */
function idDe_(qual) {
  if (!_ids) { try { _ids = PropertiesService.getScriptProperties().getProperties() || {}; } catch (e) { _ids = {}; } }
  return _ids['ID_' + qual] || CFG.IDS[qual];
}
function guardarId_(qual, id) { PropertiesService.getScriptProperties().setProperty('ID_' + qual, id); _ids = null; delete _planilhas[qual]; try { esquecer_(); } catch (e) { } }
function letraCol_(n) { let s = ''; n++; while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); } return s; }

function pastaBase_() {
  const nome = 'Sistema NG - dados';
  let pai = null;
  try { const it = DriveApp.getFileById(ScriptApp.getScriptId()).getParents(); if (it.hasNext()) pai = it.next(); } catch (e) { }
  if (!pai) { try { pai = DriveApp.getRootFolder(); } catch (e) { } }
  if (pai) { const it = pai.getFoldersByName(nome); return it.hasNext() ? it.next() : pai.createFolder(nome); }
  return DriveApp.createFolder(nome);
}

/** Confere as 4 planilhas e as 2 pastas; cria o que não abrir. forcar = lista de nomes para recriar (testes). */
function instalarPlanilhas_(forcar) {
  forcar = forcar || [];
  const feito = [];
  let base = null;
  const pegarBase = () => base || (base = pastaBase_());
  Object.keys(NOMES_PASTAS).forEach(k => {
    let ok = forcar.indexOf(k) < 0;
    if (ok) { try { DriveApp.getFolderById(idDe_(k)).getName(); } catch (e) { ok = false; } }
    if (ok) return;
    const p = pegarBase().createFolder(NOMES_PASTAS[k]); guardarId_(k, p.getId()); feito.push('pasta ' + NOMES_PASTAS[k]);
  });
  Object.keys(NOMES_PLANILHAS).forEach(k => {
    let ok = forcar.indexOf(k) < 0;
    if (ok) { try { SpreadsheetApp.openById(idDe_(k)).getSheetByName('__teste__'); } catch (e) { ok = false; } }
    if (ok) return;
    const ss = SpreadsheetApp.create(NOMES_PLANILHAS[k]);
    try { DriveApp.getFileById(ss.getId()).moveTo(pegarBase()); } catch (e) { }
    guardarId_(k, ss.getId());
    montarPlanilha_(k, ss);
    feito.push('planilha ' + NOMES_PLANILHAS[k]);
  });
  if (feito.length) console.log('Criado: ' + feito.join(', ') + '. Pasta: Sistema NG - dados.');
  return feito;
}

/** Cria as abas de uma planilha nova: cabeçalhos, códigos, listas e as contas principais. */
function montarPlanilha_(qual, ss) {
  const sobra = ss.getSheets()[0];
  Object.keys(TABELAS).filter(k => TABELAS[k].planilha === qual && k !== 'CLAUSULAS').forEach(k => {
    const t = TABELAS[k], aba = ss.insertSheet(t.aba);
    const cab = [t.id].concat(t.campos.map(c => c.c).filter(c => c !== t.id));
    aba.getRange(1, 1, 1, cab.length).setValues([cab]);
    if (aba.setFrozenRows) aba.setFrozenRows(1);
    const e = ESTRUTURA_IDS[k];
    if (e) {
      if (aba.getMaxRows && aba.getMaxRows() < e[2] + 1) aba.insertRowsAfter(aba.getMaxRows(), e[2] + 1 - aba.getMaxRows());
      aba.getRange(2, 1, e[2], 1).setValues(Array.from({ length: e[2] }, (_, i) => [e[0] + String(i + 1).padStart(e[1], '0')]));
    }
    formulasPadrao_(k, aba, cab);
  });
  if (qual === 'OPERACAO') {
    const l = ss.insertSheet('LISTAS'), nomes = Object.keys(LISTAS_PADRAO);
    l.getRange(1, 1, 1, nomes.length).setValues([nomes]);
    nomes.forEach((n, i) => {
      const v = LISTAS_PADRAO[n];
      if (v) l.getRange(2, i + 1, v.length, 1).setValues(v.map(x => [x]));
      else if (l.getRange(2, i + 1).setFormula) l.getRange(2, i + 1).setFormula("=FILTER('TIPOS DE EQUIPAMENTO'!B2:B,'TIPOS DE EQUIPAMENTO'!B2:B<>\"\")");
    });
  }
  try { if (sobra && ss.getSheets().length > 1 && ss.deleteSheet) ss.deleteSheet(sobra); } catch (e) { }
}

/** Contas que o sistema lê das planilhas (colunas "info"). Fórmulas em inglês (o Apps Script exige). */
function formulasPadrao_(tabela, aba, cab) {
  if (!aba.getRange(2, 1).setFormula) return;
  const L = n => letraCol_(cab.indexOf(n)), chave = L(TABELAS[tabela].chave);
  const por = (col, f) => { const i = cab.indexOf(col); if (i >= 0) aba.getRange(2, i + 1).setFormula('=ARRAYFORMULA(IF(' + chave + '2:' + chave + '="",,' + f + '))'); };
  if (tabela === 'ITENS_ORC' || tabela === 'MATERIAIS') por('Total', 'IFERROR(' + L('Quantidade') + '2:' + L('Quantidade') + '*' + L('Valor unitário') + '2:' + L('Valor unitário') + ',0)');
  if (tabela === 'ORCAMENTOS') {
    const it = TABELAS.ITENS_ORC, cIt = [it.id].concat(it.campos.map(c => c.c)), Li = n => letraCol_(cIt.indexOf(n));
    const ref = "'" + it.aba + "'!";
    por('Subtotal', 'SUMIF(' + ref + Li('Nº orçamento') + ':' + Li('Nº orçamento') + ',' + L('Nº orçamento') + '2:' + L('Nº orçamento') + ',' + ref + Li('Total') + ':' + Li('Total') + ')');
    por('Total', L('Subtotal') + '2:' + L('Subtotal') + '-(' + L('Desconto') + '2:' + L('Desconto') + '+0)');
    por('Válido até', 'IF(' + L('Data') + '2:' + L('Data') + '="",,' + L('Data') + '2:' + L('Data') + '+IF(' + L('Validade (dias)') + '2:' + L('Validade (dias)') + '="",7,' + L('Validade (dias)') + '2:' + L('Validade (dias)') + '))');
  }
  if (tabela === 'FIXAS') por('Pago no ano', L('Valor') + '2:' + L('Valor') + '*(' + MESES.map(m => '(' + L(m) + '2:' + L(m) + '=TRUE)').join('+') + ')');
  if (tabela === 'RESERVA') {
    const g = L('Guardei ou tirei'), v = L('Valor'), n = ESTRUTURA_IDS.RESERVA[2] + 1, r = x => x + '2:' + x + n;
    // saldo acumulado linha a linha (guardei soma, tirei subtrai)
    const i = cab.indexOf('Saldo da reserva');
    if (i >= 0) aba.getRange(2, i + 1).setFormula('=ARRAYFORMULA(IF(' + r(chave) + '=",,MMULT((ROW(' + r(v) + ')>=TRANSPOSE(ROW(' + r(v) + ')))*1,IF(' + r(g) + '="Tirei",-1,1)*(' + r(v) + '+0))))');
  }
}

/** Linhas da aba DADOS (Sistema NG). Acrescenta as que faltarem, sem mexer nos valores que já existem. */
function dadosCampos_() { return [
  ['Razão social', CFG.EMPRESA.razao, 'Nome da empresa nos documentos', 'Sim'], ['CNPJ', CFG.EMPRESA.cnpj, '', 'Sim'], ['Telefone', CFG.EMPRESA.fone, '', 'Sim'],
  ['WhatsApp (só números, com 55)', '', 'Número do WhatsApp da empresa', 'Sim'], ['E-mail', CFG.EMPRESA.email, '', 'Sim'], ['Endereço', CFG.EMPRESA.endereco, '', 'Sim'],
  ['Instagram', '', '@ da empresa', 'Sim'], ['Site', '', 'Endereço do site', 'Não'], ['Atendimento', 'Seg a sex, 8h às 18h', 'Horário que aparece no site', 'Sim'],
  ['Chave PIX', '', 'Para o QR Code PIX', 'Não'], ['Nome do recebedor PIX', '', 'Até 25 letras, sem acento', 'Não'], ['Cidade do PIX', '', 'Até 15 letras, sem acento', 'Não'],
  ['Validade do orçamento (dias)', 7, '', 'Não'], ['Condições do orçamento', 'Pagamento: PIX, dinheiro ou cartão.', 'Sai no orçamento e no contrato de serviço único', 'Não'],
  ['Garantia do serviço', '90 (noventa) dias', 'Sai na cláusula de garantia do contrato', 'Não'], ['Aviso de rescisão (dias)', 30, 'Prazo de aviso para encerrar contrato', 'Não'],
  ['Cidade do foro (contratos)', 'Uberlândia/MG', '', 'Não'], ['Responsável técnico', '', 'Nome do responsável técnico do PMOC', 'Não'],
  ['Registro do responsável técnico', '', 'CFT / CREA', 'Não'], ['WhatsApp do contador', '', 'Para mandar os relatórios ao contador (só números, com 55)', 'Não'],
  ['Token do Instagram', '', 'Fotos do Instagram no site (nunca vai para o site)', 'Não']
]; }
function garantirDadosEmpresa_() {
  const aba = abaDados_(), ja = {};
  aba.getDataRange().getValues().slice(1).forEach(r => { ja[String(r[0]).trim()] = 1; });
  const falta = dadosCampos_().filter(c => !ja[c[0]]);
  if (falta.length) aba.getRange(aba.getLastRow() + 1, 1, falta.length, 4).setValues(falta);
  CacheService.getScriptCache().remove('DADOS_EMP'); _dados = null;
  return falta.length;
}

/* ===== Limpeza.gs ===== */
/** ===================== LIMPEZA (para repassar o sistema ou depois de um treinamento) =====================
 * Apaga os dados de uso e deixa o sistema "zerado", mantendo a configuração.
 *
 * COMO USAR (no editor do Apps Script):
 *   1. Escolha a função limparSistema e clique em Executar. Ela só MOSTRA o que vai apagar (no Registro de execução).
 *   2. Para confirmar, execute limparSistema de novo em até 5 minutos. Aí sim ela apaga.
 *   Antes de apagar, ela faz uma CÓPIA DE SEGURANÇA das 4 planilhas na pasta "Backup antes da limpeza <data>".
 *   Se a cópia falhar, nada é apagado.
 *
 * APAGA: clientes, contratos, orçamentos (e itens), serviços (OS), equipamentos, acompanhamento PMOC, registros PMOC,
 *        materiais usados, movimento financeiro, reserva, presença, ponto, contatos do site, log e requisições.
 *        Nas despesas fixas, desmarca os meses pagos (as despesas continuam).
 * MANTÉM: dados da empresa, cláusulas do contrato, tipos de equipamento, checklists, tabela de preços, estoque (itens),
 *         funcionários, listas, usuários e perfis.
 * ARQUIVOS NO DRIVE (PDFs e fotos): só vão para a lixeira se LIMPEZA_APAGAR_ARQUIVOS = true (ficam 30 dias na lixeira).
 */
const LIMPEZA_APAGAR_ARQUIVOS = false;
const LIMPEZA_TABELAS = ['SERVICOS', 'CLIENTES', 'CONTRATOS', 'ORCAMENTOS', 'ITENS_ORC', 'EQUIPAMENTOS', 'PMOC', 'MATERIAIS', 'MOVIMENTO', 'RESERVA', 'PRESENCA', 'PONTO'];
const LIMPEZA_ABAS = [['OPERACAO', 'REGISTROS PMOC'], ['SISTEMA', 'CONTATOS DO SITE'], ['SISTEMA', 'LOG'], ['SISTEMA', 'REQUISIÇÕES']];

function limparSistema() {
  soDono_();
  const pr = PropertiesService.getScriptProperties(), pedida = Number(pr.getProperty('LIMPEZA_PEDIDA') || 0);
  const resumo = limpezaResumo_();
  if (!pedida || Date.now() - pedida > 5 * 60 * 1000) {
    pr.setProperty('LIMPEZA_PEDIDA', String(Date.now()));
    const msg = 'ATENÇÃO: a limpeza vai apagar:\n' + resumo.map(r => ' - ' + r).join('\n') +
      '\nAntes, será feita uma cópia de segurança das planilhas.' + (LIMPEZA_APAGAR_ARQUIVOS ? '\nOs PDFs e fotos do Drive irão para a lixeira.' : '\nOs PDFs e fotos do Drive NÃO serão apagados.') +
      '\n\nPara CONFIRMAR, execute limparSistema de novo nos próximos 5 minutos.';
    console.log(msg);
    return { confirmar: true, resumo: resumo };
  }
  pr.deleteProperty('LIMPEZA_PEDIDA');
  const backup = backupPlanilhas_();
  let n = 0;
  LIMPEZA_TABELAS.forEach(k => { n += limparTabela_(k); });
  limparMesesFixas_();
  LIMPEZA_ABAS.forEach(([p, a]) => { const s = planilha_(p).getSheetByName(a); if (s && s.getLastRow() > 1) s.deleteRows(2, s.getLastRow() - 1); });
  let arquivos = 0;
  if (LIMPEZA_APAGAR_ARQUIVOS) arquivos = lixeiraArquivos_();
  try { CacheService.getScriptCache().remove('REQBUF'); } catch (e) { }
  esquecer_();
  log_('LIMPEZA', Session.getEffectiveUser().getEmail(), n + ' registros apagados · backup: ' + backup);
  console.log('Limpeza feita: ' + n + ' registros apagados' + (arquivos ? ', ' + arquivos + ' arquivos na lixeira' : '') + '. Backup em: ' + backup);
  return { apagados: n, arquivos: arquivos, backup: backup };
}

function limpezaResumo_() {
  const out = [];
  LIMPEZA_TABELAS.forEach(k => { const n = lerTabela_(k).length; if (n) out.push(n + ' registro(s) em ' + TABELAS[k].titulo); });
  LIMPEZA_ABAS.forEach(([p, a]) => { const s = planilha_(p).getSheetByName(a); const n = s ? Math.max(0, s.getLastRow() - 1) : 0; if (n) out.push(n + ' linha(s) em ' + a); });
  return out.length ? out : ['nada (o sistema já está limpo)'];
}

/** Cópia das 4 planilhas numa pasta nova, ao lado do Financeiro. Se falhar, a limpeza para. */
function backupPlanilhas_() {
  const quando = Utilities.formatDate(new Date(), CFG.FUSO, 'yyyy-MM-dd HH-mm');
  const pasta = pastaRaiz_('fin').createFolder('Backup antes da limpeza ' + quando);
  Object.keys(NOMES_PLANILHAS).forEach(k => {
    const arq = DriveApp.getFileById(idDe_(k));
    if (!arq.makeCopy) throw new Error('Não foi possível copiar ' + NOMES_PLANILHAS[k] + '. Nada foi apagado.');
    arq.makeCopy(NOMES_PLANILHAS[k] + ' (backup ' + quando + ')', pasta);
  });
  return pasta.getUrl();
}

/** Limpa os campos de todas as linhas usadas. Os códigos (ID) e as colunas com fórmula ficam. */
function limparTabela_(tab) {
  const t = TABELAS[tab], aba = abaDe_(t), n = aba.getLastRow();
  if (n < 2) return 0;
  const cab = cabecalho_(aba.getRange(1, 1, 1, aba.getLastColumn()).getValues()[0]);
  const chaves = aba.getRange(2, cab[t.chave] + 1, n - 1, 1).getValues();
  const usadas = chaves.filter(c => String(c[0]).trim() !== '').length;
  if (!usadas) return 0;
  t.campos.forEach(c => {
    if ((SO_LEITURA[c.t] && !c.sistema) || cab[c.c] === undefined || c.c === t.id) return;
    aba.getRange(2, cab[c.c] + 1, n - 1, 1).setValues(Array.from({ length: n - 1 }, () => [c.t === 'bool' ? false : '']));
  });
  if (cab['Origem'] !== undefined) aba.getRange(2, cab['Origem'] + 1, n - 1, 1).setValues(Array.from({ length: n - 1 }, () => ['']));
  return usadas;
}
function limparMesesFixas_() {
  const t = TABELAS.FIXAS, aba = abaDe_(t), n = aba.getLastRow();
  if (n < 2) return;
  const cab = cabecalho_(aba.getRange(1, 1, 1, aba.getLastColumn()).getValues()[0]);
  MESES.concat(['Última baixa']).forEach(m => { if (cab[m] !== undefined) aba.getRange(2, cab[m] + 1, n - 1, 1).setValues(Array.from({ length: n - 1 }, () => [m === 'Última baixa' ? '' : false])); });
}
/** PDFs e fotos gerados pelo sistema vão para a lixeira (dá para recuperar por 30 dias). */
function lixeiraArquivos_() {
  let n = 0;
  const varrer = p => { const f = p.getFiles(); while (f.hasNext()) { f.next().setTrashed(true); n++; } const s = p.getFolders ? p.getFolders() : null; while (s && s.hasNext()) varrer(s.next()); };
  ['PASTA_DOCS', 'PASTA_FOTOS'].forEach(k => { try { const p = DriveApp.getFolderById(idDe_(k)), s = p.getFolders(); while (s.hasNext()) varrer(s.next()); } catch (e) { } });
  try { const r = pastaRaiz_('fin').getFoldersByName('Relatórios do contador'); if (r.hasNext()) varrer(r.next()); } catch (e) { }
  return n;
}

/* ===== Marca.gs ===== */
/** Imagens do logo usadas nos documentos em PDF: arcos com NG AR dentro + 'Condicionado' ao lado, e a marca d'agua (so os arcos com NG AR). Nao precisa mexer. */
const LOGO_PNG = 'data:image/png;base64,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';
const LOGO_MARCA_DAGUA = 'data:image/png;base64,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';

/* ===== ModelosBase.gs ===== */
/** Checklists e tipos ORIGINAIS da NG (os mesmos da planilha). Usados só numa instalação nova (planilha vazia).
 * Gerado a partir de pmoc/chk.json e pmoc/tipos.json. Formato igual ao de ModelosPmoc.gs. */
const MODELOS_BASE_CHECKLIST = {
 'Chiller': [
  'M|Evaporadora|Inspecionar e remover impurezas da carenagem externa',
  'M|Evaporadora|Inspecionar e higienizar o reservatório de água gelada (se aplicável)',
  'M|Evaporadora|Inspecionar e mitigar ruídos ou vibrações fora da normalidade',
  'M|Evaporadora|Verificar e ajustar o nível do fluido no reservatório de água gelada (se aplicável)',
  'B|Evaporadora|Inspecionar a estanqueidade dos circuitos frigoríficos (detecção de vazamentos)',
  'T|Evaporadora|Verificar a operação da bomba de circulação (incluindo o sentido de rotação)',
  'M|Evaporadora|Registrar a pressão do circuito de água gelada|bar',
  'M|Evaporadora|Registrar a temperatura de saída da água no evaporador|°C',
  'M|Evaporadora|Registrar a temperatura de entrada da água no evaporador|°C',
  'M|Evaporadora|Inspecionar a condição dos amortecedores de vibração',
  'M|Evaporadora|Inspecionar e limpar o filtro tipo \'Y\'',
  'T|Evaporadora|Executar a retrolavagem (lavagem em contracorrente)',
  'M|Condensadora|Inspecionar e higienizar o condensador',
  'M|Condensadora|Inspecionar e tensionar as correias dos ventiladores (se houver)',
  'M|Condensadora|Registrar a pressão do circuito de água do condensador|bar',
  'M|Condensadora|Inspecionar visualmente o filtro secador',
  'M|Condensadora|Inspecionar o visor de umidade',
  'T|Condensadora|Corrente do trocador de calor · fase R|A',
  'T|Condensadora|Corrente do trocador de calor · fase S|A',
  'T|Condensadora|Corrente do trocador de calor · fase T|A',
  'T|Condensadora|Corrente do compressor · fase R|A',
  'T|Condensadora|Corrente do compressor · fase S|A',
  'T|Condensadora|Corrente do compressor · fase T|A',
  'S|Condensadora|Registrar a pressão de sucção|psi',
  'S|Condensadora|Registrar a pressão de descarga|psi'
 ],
 'Fan coil': [
  'S|Fan coil|Verificar estado e alinhamento da(s) polia(s)',
  'M|Fan coil|Verificar e desentupir os drenos',
  'M|Fan coil|Verificar e remover ferrugem do ventilador',
  'M|Fan coil|Verificar e corrigir tensão e estado da(s) correia(s)',
  'A|Fan coil|Verificar e remover ferrugem da bandeja',
  'T|Fan coil|Verificar funcionamento da válvula motorizada',
  'M|Fan coil|Verificar existência de ruídos e vibrações',
  'S|Fan coil|Verificar o isolamento térmico do gabinete',
  'M|Fan coil|Verificar atuação da válvula motorizada para controle de vazão',
  'M|Fan coil|Verificar resistência de aquecimento e umidificação (se existir)',
  'T|Fan coil|Lavar ou trocar os filtros de ar',
  'S|Fan coil|Corrigir tampas soltas do gabinete e vedação',
  'M|Fan coil|Purgar ar da serpentina',
  'T|Fan coil|Lubrificar mancais e rolamentos',
  'T|Fan coil|Manobrar cada registro e válvula até o fim de curso e voltar à posição original',
  'S|Fan coil|Lavar serpentina e bandeja com remoção do biofilme',
  'S|Fan coil|Lavar voluta e rotor dos ventiladores',
  'T|Fan coil|Limpar filtro de água',
  'S|Fan coil|Medir temperatura de entrada da água gelada|°C',
  'M|Fan coil|Medir temperatura de saída da água gelada|°C'
 ],
 'Split': [
  'M|Condicionador|Verificar existência de ruídos e vibrações anormais',
  'T|Condicionador|Limpar voluta e rotor dos ventiladores',
  'M|Condicionador|Registrar temperatura do ar de insuflamento|°C',
  'M|Condicionador|Verificar e desentupir os drenos',
  'T|Condicionador|Lavar serpentina e bandeja',
  'S|Condicionador|Verificar o isolamento térmico do gabinete',
  'S|Condicionador|Corrigir tampas soltas do gabinete e vedação',
  'M|Condicionador|Lavar ou trocar os filtros de ar',
  'T|Condicionador|Lavar serpentina do condensador e limpar o gabinete',
  'T|Condicionador|Verificar a existência de vazamentos de gás',
  'S|Condicionador|Verificar isolamento térmico das tubulações',
  'S|Condicionador|Limpeza geral do equipamento, incluindo motores e compressores',
  'M|Condicionador|Registrar temperatura do ar de retorno|°C',
  'T|Condicionador|Verificar e limpar o condensador',
  'T|Quadro elétrico|Verificar e substituir lâmpadas e fusíveis',
  'S|Quadro elétrico|Reapertar terminais, parafusos e molas',
  'S|Quadro elétrico|Verificar aperto dos fusíveis',
  'S|Quadro elétrico|Verificar e limpar contatoras'
 ],
 'Piso teto': [
  'M|Condicionador|Todas as funções estão operando',
  'M|Condicionador|Verificar obstruções na passagem de ar de insuflamento e retorno',
  'M|Condicionador|Limpar o filtro de ar',
  'M|Condicionador|Verificar estado dos filtros de ar descartáveis',
  'M|Condicionador|Verificar se a água de condensação está sendo drenada livremente',
  'M|Condicionador|Limpar a bandeja de drenagem',
  'T|Condicionador|Verificar o funcionamento dos dispositivos de proteção e acionamento',
  'S|Condicionador|Reapertar os conectores elétricos',
  'T|Condicionador|Verificar superaquecimento de cabos ou conectores e substituir conexões defeituosas',
  'T|Condicionador|Limpar as serpentinas interna e externa',
  'S|Condicionador|Eliminar focos de oxidação (lixamento e pintura)',
  'S|Condicionador|Vistoriar e corrigir o isolamento das linhas frigorígenas',
  'T|Condicionador|Vistoriar circuitos e eliminar vazamentos',
  'S|Condicionador|Lavar a serpentina e o ventilador da unidade evaporadora',
  'A|Condicionador|Verificar isolação elétrica de motores e compressores',
  'M|Condicionador|Preencher relatório de manutenção',
  'T|Medições|Pressão de funcionamento · alta|psi',
  'T|Medições|Pressão de funcionamento · baixa|psi',
  'M|Medições|Tensão elétrica · RS|V',
  'M|Medições|Tensão elétrica · RT|V',
  'M|Medições|Tensão elétrica · ST|V',
  'M|Medições|Corrente elétrica · R|A',
  'M|Medições|Corrente elétrica · S|A',
  'M|Medições|Corrente elétrica · T|A',
  'M|Medições|Temperatura do ar · insuflamento|°C',
  'M|Medições|Temperatura do ar · retorno|°C'
 ]
};
const MODELOS_BASE_TIPOS = [['Split hi-wall (de parede)','Split'],['Split dutado (splitão)','Piso teto'],['Self contained (gabinete)','Piso teto'],['ACJ (de janela)','Split'],['Split piso-teto','Piso teto'],['Split cassete (de teto)','Piso teto'],['Chiller','Chiller'],['Fan coil','Fan coil'],['Climatizador evaporativo','Split'],['VRF / multi-split','Split'],['Outro','Split']];

/* ===== ModelosPmoc.gs ===== */
/** ===================== MODELOS DE PMOC (tipos de equipamento e checklists) =====================
 * Acrescenta nas abas TIPOS DE EQUIPAMENTO e CHECKLIST PMOC os modelos abaixo, sem duplicar nem mexer no que já existe.
 * Roda sozinho no configuracaoInicial; dá para rodar de novo quando quiser (instalarModelosPmoc no editor).
 * As periodicidades são SUGESTÕES de mercado (base: Portaria 3.523/98, RE 09/2003 e NBR 13971).
 * Quem define as rotinas e os prazos de cada cliente é o responsável técnico: ajuste na planilha.
 *
 * Formato de cada item: 'P|Grupo|Atividade' ou 'P|Grupo|Medição|unidade' (com unidade = resposta por medição).
 * P = M mensal · B bimestral · T trimestral · S semestral · A anual
 */
const PER_SIGLA = { M: 'Mensal', B: 'Bimestral', T: 'Trimestral', S: 'Semestral', A: 'Anual' };

const MODELOS_CHECKLIST = {
  'Cassete': [
    'M|Evaporadora|Limpar os filtros de ar', 'M|Evaporadora|Limpar a grelha e o painel frontal', 'M|Evaporadora|Verificar ruídos e vibrações anormais',
    'M|Dreno|Verificar a bomba de dreno e o escoamento do condensado', 'M|Dreno|Limpar a bandeja de condensado', 'M|Medições|Temperatura do ar de insuflamento|°C',
    'M|Medições|Temperatura do ar de retorno|°C', 'T|Evaporadora|Limpar a serpentina da evaporadora', 'T|Evaporadora|Limpar a turbina e o motor do ventilador',
    'T|Condensadora|Limpar a serpentina da condensadora', 'T|Elétrica|Reapertar bornes e conexões elétricas', 'T|Medições|Corrente do compressor|A', 'T|Medições|Tensão de alimentação|V',
    'S|Refrigeração|Verificar vazamentos nas conexões e linhas', 'S|Refrigeração|Verificar o isolamento térmico das linhas', 'S|Medições|Pressão de sucção|psi',
    'A|Evaporadora|Higienizar a serpentina com produto bactericida', 'A|Geral|Verificar fixação e suportes das unidades'
  ],
  'Dutado / Splitão': [
    'M|Evaporadora|Limpar ou trocar os filtros de ar', 'M|Evaporadora|Verificar ruídos e vibrações anormais', 'M|Dreno|Limpar a bandeja e o dreno de condensado',
    'M|Transmissão|Verificar tensão e estado das correias', 'M|Medições|Temperatura do ar de insuflamento|°C', 'M|Medições|Temperatura do ar de retorno|°C',
    'B|Transmissão|Verificar alinhamento das polias', 'T|Evaporadora|Limpar a serpentina da evaporadora', 'T|Evaporadora|Limpar o rotor e a voluta do ventilador',
    'T|Condensadora|Limpar a serpentina da condensadora', 'T|Elétrica|Reapertar terminais e conexões do quadro', 'T|Elétrica|Verificar contatores e relés',
    'T|Medições|Corrente do compressor|A', 'T|Medições|Corrente do motor do ventilador|A', 'T|Medições|Tensão de alimentação|V',
    'S|Transmissão|Lubrificar mancais e rolamentos', 'S|Refrigeração|Verificar vazamentos de gás refrigerante', 'S|Medições|Pressão de sucção|psi', 'S|Medições|Pressão de descarga|psi',
    'S|Dutos|Verificar as conexões flexíveis e a vedação do gabinete', 'A|Dutos|Inspecionar a limpeza interna dos dutos', 'A|Geral|Verificar o isolamento térmico do gabinete e das linhas'
  ],
  'Janela (ACJ)': [
    'M|Geral|Limpar o filtro de ar', 'M|Geral|Verificar ruídos e vibrações', 'M|Geral|Verificar o escoamento da água de condensação', 'M|Medições|Temperatura do ar de insuflamento|°C',
    'T|Geral|Limpar a serpentina da evaporadora e do condensador', 'T|Elétrica|Verificar o cabo, o plugue e a tomada', 'T|Medições|Corrente de funcionamento|A',
    'S|Geral|Limpar o ventilador e a bandeja', 'A|Geral|Higienizar o aparelho com produto bactericida', 'A|Geral|Verificar a vedação e a fixação na parede'
  ],
  'Portátil': [
    'M|Geral|Limpar os filtros de ar', 'M|Geral|Esvaziar e limpar o reservatório de condensado', 'M|Geral|Verificar a mangueira de exaustão',
    'T|Geral|Limpar as serpentinas', 'T|Elétrica|Verificar o cabo e o plugue', 'S|Geral|Higienizar com produto bactericida'
  ],
  'VRF - evaporadora': [
    'M|Evaporadora|Limpar os filtros de ar', 'M|Evaporadora|Verificar ruídos e vibrações', 'M|Dreno|Verificar o dreno e a bomba de condensado',
    'M|Controle|Verificar o controle remoto ou central e os códigos de erro', 'M|Medições|Temperatura do ar de insuflamento|°C', 'M|Medições|Temperatura do ar de retorno|°C',
    'T|Evaporadora|Limpar a serpentina', 'T|Evaporadora|Limpar a turbina do ventilador', 'T|Dreno|Limpar a bandeja de condensado', 'T|Elétrica|Reapertar bornes e a linha de comunicação',
    'S|Refrigeração|Verificar o isolamento das linhas e das conexões', 'A|Evaporadora|Higienizar a serpentina com produto bactericida'
  ],
  'VRF - condensadora': [
    'M|Condensadora|Verificar ruídos e vibrações', 'M|Controle|Verificar o histórico de alarmes e erros', 'M|Condensadora|Verificar a limpeza externa e a área livre de circulação de ar',
    'T|Condensadora|Limpar a serpentina da condensadora', 'T|Elétrica|Reapertar terminais do quadro e da placa', 'T|Medições|Corrente total da unidade|A', 'T|Medições|Tensão entre fases|V',
    'S|Refrigeração|Verificar vazamentos de gás refrigerante', 'S|Medições|Pressão de alta|psi', 'S|Medições|Pressão de baixa|psi',
    'S|Condensadora|Verificar os ventiladores e as hélices', 'A|Elétrica|Medir a isolação dos compressores (megômetro)', 'A|Geral|Verificar suportes, amortecedores e fixação'
  ],
  'Self contained': [
    'M|Gabinete|Limpar ou trocar os filtros de ar', 'M|Gabinete|Verificar ruídos e vibrações', 'M|Dreno|Limpar a bandeja e o dreno', 'M|Transmissão|Verificar as correias',
    'M|Medições|Temperatura do ar de insuflamento|°C', 'M|Medições|Temperatura do ar de retorno|°C', 'T|Gabinete|Limpar a serpentina da evaporadora',
    'T|Condensação|Limpar o condensador (a ar ou a água)', 'T|Transmissão|Verificar polias e lubrificar mancais', 'T|Elétrica|Reapertar terminais e verificar contatores',
    'T|Medições|Corrente dos compressores|A', 'T|Medições|Tensão de alimentação|V', 'S|Refrigeração|Verificar vazamentos de gás refrigerante', 'S|Medições|Pressão de sucção|psi',
    'S|Medições|Pressão de descarga|psi', 'S|Condensação|Verificar a vazão e a temperatura da água de condensação (se a água)', 'A|Gabinete|Verificar o isolamento térmico e a vedação'
  ],
  'Rooftop': [
    'M|Unidade|Limpar ou trocar os filtros de ar', 'M|Unidade|Verificar ruídos e vibrações', 'M|Unidade|Verificar as correias e as polias', 'M|Dreno|Limpar a bandeja e o dreno',
    'M|Medições|Temperatura do ar de insuflamento|°C', 'B|Unidade|Verificar o damper de ar externo', 'T|Unidade|Limpar as serpentinas', 'T|Elétrica|Reapertar terminais e verificar contatores',
    'T|Medições|Corrente dos compressores|A', 'T|Medições|Corrente do ventilador|A', 'S|Unidade|Lubrificar mancais', 'S|Refrigeração|Verificar vazamentos',
    'S|Medições|Pressão de sucção|psi', 'S|Medições|Pressão de descarga|psi', 'A|Unidade|Verificar a vedação do gabinete e a cobertura', 'A|Unidade|Verificar a corrosão da estrutura'
  ],
  'Fan coil (modelo HBC)': [
    'M|Serviços mensais|Limpar externa e internamente o condicionador', 'M|Serviços mensais|Limpar o sistema de drenagem e a bandeja de condensado', 'M|Serviços mensais|Verificar vibrações anormais',
    'M|Serviços mensais|Verificar fixação e alinhamento das polias do ventilador', 'M|Serviços mensais|Verificar o estado das correias e suas tensões', 'M|Serviços mensais|Verificar vazamento de água',
    'M|Serviços mensais|Verificar os fechos das tampas e os parafusos dos painéis', 'M|Serviços mensais|Verificar e limpar a serpentina', 'M|Serviços mensais|Limpar os filtros de linha (água gelada)',
    'B|Serviços bimestrais|Verificar funcionamento do sensor, controlador e atuador da válvula de água gelada', 'B|Serviços bimestrais|Verificar a operação dos dispositivos de sinalização e alarme',
    'B|Serviços bimestrais|Verificar e limpar os contatos das chaves magnéticas', 'T|Serviços trimestrais|Verificar e ajustar a atuação da válvula de 3 vias',
    'T|Serviços trimestrais|Verificar a fixação de terminais, cabos e conexões elétricas', 'T|Serviços trimestrais|Verificar o aperto dos terminais elétricos',
    'T|Serviços trimestrais|Tensão de funcionamento|V', 'T|Serviços trimestrais|Corrente de funcionamento|A', 'T|Serviços trimestrais|Verificar focos de oxidação',
    'T|Serviços trimestrais|Verificar e limpar rotores e hélices dos ventiladores', 'S|Serviços semestrais|Verificar acoplamentos e juntas flexíveis',
    'S|Serviços semestrais|Verificar e ajustar dispositivos de medição, controle e segurança (relé térmico, termostato, manômetro e termômetro)',
    'S|Serviços semestrais|Verificar e ajustar a regulagem dos sensores de ambiente', 'S|Serviços semestrais|Lubrificar os mancais',
    'A|Serviços anuais|Manobrar cada registro hidráulico do início ao fim do curso', 'A|Serviços anuais|Verificar o estado das conexões flexíveis dos dutos',
    'A|Serviços anuais|Verificar revestimentos protetores e isolamento térmico do gabinete, tubulações, válvulas e dutos'
  ],
  'Torre de resfriamento': [
    'M|Bacia|Verificar o nível e a boia de reposição de água', 'M|Bacia|Limpar a bacia e o filtro de sucção', 'M|Ventilador|Verificar ruídos e vibrações', 'M|Água|Verificar o tratamento químico da água',
    'M|Medições|Temperatura da água de entrada|°C', 'M|Medições|Temperatura da água de saída|°C', 'T|Ventilador|Verificar correias, polias e o redutor', 'T|Enchimento|Verificar o enchimento e os eliminadores de gotas',
    'T|Distribuição|Limpar os bicos de distribuição de água', 'T|Elétrica|Reapertar terminais e verificar contatores', 'T|Medições|Corrente do motor do ventilador|A',
    'S|Ventilador|Lubrificar mancais e trocar o óleo do redutor (se houver)', 'S|Estrutura|Verificar corrosão e vazamentos da estrutura', 'A|Bacia|Desinfecção completa do sistema (controle de Legionella)'
  ],
  'Bomba de água gelada': [
    'M|Bomba|Verificar ruídos, vibrações e aquecimento', 'M|Bomba|Verificar vazamentos no selo mecânico ou gaxeta', 'M|Medições|Pressão de sucção|kgf/cm²', 'M|Medições|Pressão de recalque|kgf/cm²',
    'T|Elétrica|Reapertar terminais e verificar contatores', 'T|Medições|Corrente do motor|A', 'T|Hidráulica|Limpar o filtro Y', 'S|Bomba|Lubrificar os rolamentos',
    'S|Bomba|Verificar o alinhamento do acoplamento', 'A|Hidráulica|Manobrar os registros e verificar as válvulas de retenção', 'A|Elétrica|Medir a isolação do motor (megômetro)'
  ],
  'Climatizador evaporativo': [
    'M|Reservatório|Drenar e limpar o reservatório de água', 'M|Painel|Limpar o painel evaporativo (colmeia)', 'M|Geral|Verificar a boia e a reposição de água',
    'M|Geral|Verificar ruídos e vibrações', 'T|Bomba|Limpar a bomba e a distribuição de água', 'T|Elétrica|Verificar cabos e conexões', 'S|Painel|Trocar o painel evaporativo se estiver desgastado',
    'A|Geral|Higienizar todo o equipamento com produto bactericida'
  ],
  'Cortina de ar': [
    'M|Geral|Limpar a grade de entrada de ar', 'M|Geral|Verificar ruídos e vibrações', 'T|Geral|Limpar a turbina e o motor', 'T|Elétrica|Verificar cabos, chave e sensor de porta',
    'S|Medições|Corrente do motor|A', 'A|Geral|Verificar a fixação e os suportes'
  ],
  'Exaustão e ventilação': [
    'M|Ventilador|Verificar ruídos e vibrações', 'M|Filtros|Limpar ou trocar os filtros (renovação de ar)', 'M|Geral|Verificar se as grelhas e venezianas estão desobstruídas',
    'T|Ventilador|Limpar o rotor e a carcaça', 'T|Transmissão|Verificar correias e polias', 'T|Elétrica|Reapertar terminais', 'T|Medições|Corrente do motor|A',
    'S|Ventilador|Lubrificar mancais', 'S|Dampers|Verificar o funcionamento dos dampers e registros', 'A|Medições|Vazão de ar exterior (renovação)|m³/h'
  ],
  'Rede de dutos e difusores': [
    'M|Difusores|Limpar grelhas, difusores e venezianas', 'T|Dutos|Verificar vazamentos de ar nas juntas', 'S|Dutos|Verificar o isolamento térmico dos dutos',
    'S|Dutos|Inspecionar a sujeira interna dos dutos (amostragem)', 'A|Dutos|Limpeza interna dos dutos, quando a inspeção indicar', 'A|Dampers|Verificar o funcionamento dos dampers corta-fogo e de regulagem'
  ],
  'Câmara fria': [
    'M|Câmara|Verificar a vedação das portas e as borrachas', 'M|Evaporador|Verificar o degelo e o dreno', 'M|Câmara|Verificar a iluminação e o alarme de pessoa presa',
    'M|Medições|Temperatura interna da câmara|°C', 'T|Evaporador|Limpar a serpentina do evaporador', 'T|Condensadora|Limpar a serpentina da condensadora', 'T|Elétrica|Reapertar terminais e verificar o controlador',
    'T|Medições|Corrente do compressor|A', 'S|Refrigeração|Verificar vazamentos de gás refrigerante', 'S|Medições|Pressão de sucção|psi', 'S|Medições|Pressão de descarga|psi',
    'A|Câmara|Verificar painéis, piso e isolamento'
  ],
  'Qualidade do ar (ambiente)': [
    'M|Ambiente|Verificar se há fontes de poluição ou mofo no ambiente', 'M|Medições|Temperatura do ambiente|°C', 'M|Medições|Umidade relativa do ar|%',
    'S|Medições|Concentração de CO₂|ppm', 'S|Medições|Velocidade do ar na altura de 1,5 m|m/s', 'S|Análise|Coleta para análise de fungos (RE 09/2003)',
    'S|Análise|Coleta para análise de aerodispersóides (RE 09/2003)', 'A|Documentação|Atualizar o PMOC e o laudo da qualidade do ar'
  ]
};

const MODELOS_TIPOS = [
  ['Split cassete 4 vias', 'Cassete'], ['Split cassete 1 via', 'Cassete'], ['Split dutado (built-in)', 'Dutado / Splitão'], ['Splitão (dutado de alta capacidade)', 'Dutado / Splitão'],
  ['Ar-condicionado de janela', 'Janela (ACJ)'], ['Ar-condicionado portátil', 'Portátil'], ['Multi-split (evaporadora)', 'Split'], ['Split inverter hi-wall', 'Split'],
  ['VRF / VRV evaporadora', 'VRF - evaporadora'], ['VRF / VRV condensadora', 'VRF - condensadora'], ['Self contained a ar', 'Self contained'], ['Self contained a água', 'Self contained'],
  ['Rooftop', 'Rooftop'], ['Fan coil (modelo HBC)', 'Fan coil (modelo HBC)'], ['Fancolete (fan coil pequeno)', 'Fan coil'], ['Chiller a ar', 'Chiller'], ['Chiller a água', 'Chiller'],
  ['Torre de resfriamento', 'Torre de resfriamento'], ['Bomba de água gelada / condensação', 'Bomba de água gelada'], ['Climatizador evaporativo industrial', 'Climatizador evaporativo'],
  ['Cortina de ar', 'Cortina de ar'], ['Exaustor / ventilador', 'Exaustão e ventilação'], ['Caixa de ventilação (renovação de ar)', 'Exaustão e ventilação'],
  ['Rede de dutos e difusores', 'Rede de dutos e difusores'], ['Câmara fria / refrigeração comercial', 'Câmara fria'], ['Ambiente climatizado (qualidade do ar)', 'Qualidade do ar (ambiente)']
];

/** Grava linhas na aba: usa primeiro as linhas livres (com ID e sem a coluna-chave) e depois acrescenta no fim. */
function preencherLivres_(tabela, linhas) {
  if (!linhas.length) return 0;
  const def = TABELAS[tabela], aba = planilha_(def.planilha).getSheetByName(def.aba);
  const v = aba.getDataRange().getValues(), cab = cabecalho_(v[0]), nc = v[0].length;
  const livres = []; for (let r = 1; r < v.length; r++) if (String(v[r][cab[def.chave]] || '').trim() === '' && String(v[r][cab[def.id]] || '').trim() !== '') livres.push(r);
  const ultimoId = v.slice(1).map(r => String(r[cab[def.id]] || '')).filter(Boolean).pop() || '';
  const m = ultimoId.match(/^(.*?)(\d+)$/); let seq = m ? Number(m[2]) : 0; const pre = m ? m[1] : '', dig = m ? m[2].length : 4;
  const alvo = [];
  linhas.forEach((o, i) => {
    let r;
    if (i < livres.length) r = livres[i]; else { r = v.length; v.push(new Array(nc).fill('')); v[r][cab[def.id]] = pre + String(++seq).padStart(dig, '0'); }
    Object.keys(o).forEach(k => { if (cab[k] != null) v[r][cab[k]] = o[k]; });
    alvo.push(r);
  });
  // grava só as colunas conhecidas e só as linhas novas (em blocos seguidos), sem tocar no resto da aba
  const cols = Object.keys(linhas[0]).map(k => cab[k]).filter(c => c != null).concat([cab[def.id]]);
  const c0 = Math.min.apply(null, cols), c1 = Math.max.apply(null, cols);
  const blocos = [];
  alvo.forEach(r => { const b = blocos[blocos.length - 1]; if (b && b.fim === r - 1) b.fim = r; else blocos.push({ ini: r, fim: r }); });
  blocos.forEach(b => aba.getRange(b.ini + 1, c0 + 1, b.fim - b.ini + 1, c1 - c0 + 1).setValues(v.slice(b.ini, b.fim + 1).map(l => l.slice(c0, c1 + 1))));
  return linhas.length;
}

/** ===================== BANCO DE ITENS =====================
 * Aba BANCO DE ITENS (Operação NG): a biblioteca de atividades, organizada por grupo (Evaporadora, Elétrica, Medições…).
 * Na primeira vez é preenchida com os itens de todos os checklists (sem repetir). Depois é mantida pelo sistema
 * (PMOC > Banco de itens). Os checklists puxam itens daqui pelo botão "Trazer itens do banco".
 */
const CAB_BANCO = ['ID', 'Grupo', 'Item', 'Periodicidade', 'Resposta', 'Unidade'];
function abaBanco_() {
  const ss = planilha_('OPERACAO');
  let aba = ss.getSheetByName('BANCO DE ITENS');
  if (!aba) aba = ss.insertSheet('BANCO DE ITENS');
  if (aba.getLastRow() < 2) {
    const vistos = {}, linhas = [];
    lerTabela_('CHECKLIST').slice().sort((a, b) => (num_(a['Ordem']) || 9999) - (num_(b['Ordem']) || 9999)).forEach(x => {
      const k = normalizar_(x['Item']); if (!k || vistos[k]) return; vistos[k] = 1;
      linhas.push([x['Grupo'] || 'Geral', x['Item'], x['Periodicidade'] || 'Mensal', x['Resposta'] || 'OK/NOK/NA', x['Unidade'] || '']);
    });
    const total = linhas.length + 200; // linhas com código sobrando para itens novos
    aba.getRange(1, 1, 1, CAB_BANCO.length).setValues([CAB_BANCO]);
    aba.getRange(2, 1, total, CAB_BANCO.length).setValues(Array.from({ length: total }, (_, i) => ['ITM-' + String(i + 1).padStart(4, '0')].concat(linhas[i] || ['', '', '', '', ''])));
  }
  return aba;
}

/** Copia itens do BANCO para o checklist "destino" (mantém grupo, periodicidade e resposta), sem repetir os que ele já tem. */
function checklistCopiar_(u, d) {
  const destino = String(d.destino || '').trim();
  if (!destino) throw erroUsuario_('Escolha em qual checklist os itens vão entrar.');
  const todos = lerTabela_('CHECKLIST'), banco = lerTabela_('BANCO'), ja = {};
  todos.filter(x => x['Checklist'] === destino).forEach(x => { ja[normalizar_(x['Item'])] = 1; });
  let ordem = todos.reduce((s, x) => Math.max(s, num_(x['Ordem']) || 0), 0);
  const linhas = [];
  (d.ids || []).forEach(id => {
    const x = banco.find(t => t._id === String(id));
    if (!x || ja[normalizar_(x['Item'])]) return;
    ja[normalizar_(x['Item'])] = 1;
    linhas.push({ 'Checklist': destino, 'Grupo': x['Grupo'] || 'Geral', 'Item': x['Item'], 'Periodicidade': x['Periodicidade'] || 'Mensal', 'Resposta': x['Resposta'] || 'OK/NOK/NA',
      'Unidade': x['Unidade'] || '', 'Ativo?': 'Sim', 'Ordem': ++ordem });
  });
  if (!linhas.length) throw erroUsuario_('Nada para acrescentar: o checklist "' + destino + '" já tem esses itens.');
  preencherLivres_('CHECKLIST', linhas);
  esquecer_();
  log_('CHECKLIST_COPIAR', u.login, linhas.length + ' item(ns) para ' + destino);
  return { adicionados: linhas.length, destino: destino };
}

/** Acrescenta os tipos de equipamento e os checklists que ainda não existem. Pode rodar várias vezes. */
function instalarModelosPmoc() {
  const jaCk = {}, jaItem = {};
  lerTabela_('CHECKLIST').forEach(x => { jaCk[x['Checklist']] = 1; jaItem[normalizar_(x['Checklist'] + '|' + x['Item'])] = 1; });
  const maxOrdem = lerTabela_('CHECKLIST').reduce((s, x) => Math.max(s, num_(x['Ordem']) || 0), 0);
  let ordem = maxOrdem;
  const itens = [];
  const todos = Object.assign({}, MODELOS_BASE_CHECKLIST, MODELOS_CHECKLIST); // originais da NG primeiro (só entram numa planilha nova)
  Object.keys(todos).forEach(ck => {
    if (jaCk[ck]) return; // checklist que já existe fica como está (pode ter sido ajustado à mão)
    todos[ck].forEach(s => {
      const p = s.split('|');
      if (jaItem[normalizar_(ck + '|' + p[2])]) return;
      itens.push({ 'Checklist': ck, 'Grupo': p[1], 'Item': p[2], 'Periodicidade': PER_SIGLA[p[0]] || 'Mensal', 'Resposta': p[3] ? 'Medição' : 'OK/NOK/NA', 'Unidade': p[3] && p[3] !== '-' ? p[3] : '', 'Ativo?': 'Sim', 'Ordem': ++ordem });
    });
  });
  const nItens = preencherLivres_('CHECKLIST', itens);
  const jaTipo = {}; lerTabela_('TIPOS_EQ').forEach(t => { jaTipo[normalizar_(t['Tipo de equipamento'])] = 1; });
  const base = {}; MODELOS_BASE_TIPOS.forEach(t => base[t[0]] = 1);
  const tipos = MODELOS_BASE_TIPOS.concat(MODELOS_TIPOS).filter(t => !jaTipo[normalizar_(t[0])] && (jaTipo[normalizar_(t[0])] = 1))
    .map(t => ({ 'Tipo de equipamento': t[0], 'Checklist PMOC': t[1], 'Observação': base[t[0]] ? '' : 'Modelo sugerido · revisar com o responsável técnico' }));
  const nTipos = preencherLivres_('TIPOS_EQ', tipos);
  esquecer_();
  const msg = 'Modelos de PMOC: ' + nTipos + ' tipo(s) de equipamento e ' + nItens + ' item(ns) de checklist acrescentados.';
  console.log(msg);
  return { tipos: nTipos, itens: nItens };
}

/* ===== Modulos.gs ===== */
/** ===================== MÓDULOS ESPECIAIS ===================== */
const FECHADOS = ['CONCLUIDO', 'CANCELADO'];
function tem_(u, m) { return u.modulos.indexOf(m) >= 0; }
function minutos_(hhmm) { const m = String(hhmm || '').match(/^(-?\d+):(\d{2})/); return m ? Number(m[1]) * 60 + Number(m[2]) : 0; }
function hhmm_(min) { return Math.floor(min / 60) + ':' + ('0' + (min % 60)).slice(-2); }
function dataDe_(s) { const m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? new Date(+m[1], +m[2] - 1, +m[3]) : null; }
function num_(v) {
  if (typeof v === 'number') return v;
  const s = String(v || '').replace(/[R$\s]/g, '');
  if (!s || s === '-') return 0;
  const n = s.indexOf(',') >= 0 ? Number(s.replace(/\./g, '').replace(',', '.')) : Number(s);
  return isNaN(n) ? 0 : n;
}
function exemplo_(txt) { return /\(apague\)|apague\)/i.test(String(txt || '')); }

/** ===================== PAINEL ===================== */
function painel_(u) {
  const hoje = hoje_(), ini = new Date(hoje.getFullYear(), hoje.getMonth(), 1), fim = new Date(hoje.getFullYear(), hoje.getMonth() + 1, 0);
  const em7 = new Date(hoje.getTime() + 7 * 864e5);
  const noMesD = d => d && d >= ini && d <= fim;
  const out = { servicos: null, lembretes: [], financeiro: null, atualizado: agoraTxt_() };

  /* --- Serviços --- */
  const s = lerTabela_('SERVICOS');
  const abertos = s.filter(x => FECHADOS.indexOf(normalizar_(x['Situação'])) < 0);
  const concl = s.filter(x => normalizar_(x['Situação']) === 'CONCLUIDO');
  out.servicos = {
    cards: [
      { titulo: 'Em aberto', valor: abertos.length, ir: 'servicos' },
      { titulo: 'Atrasados', valor: s.filter(x => x['Alerta'] === 'Atrasado').length, alerta: true, ir: 'servicos' },
      { titulo: 'Próximos 7 dias', valor: abertos.filter(x => { const d = dataDe_(x['Agendado para']); return d && d >= hoje && d <= em7; }).length, ir: 'servicos' },
      { titulo: 'Concluídos no mês', valor: concl.filter(x => noMesD(dataDe_(x['Concluído em']))).length, ir: 'servicos' }
    ],
    proximos: abertos.slice().sort((a, b) => String(a['Agendado para'] || '9').localeCompare(String(b['Agendado para'] || '9')))
      .slice(0, 8).map(x => ({ id: x._id, cliente: x['Cliente'], tipo: x['Tipo'], data: x['Agendado para'], tecnico: x['Técnico'], situacao: x['Situação'], alerta: x['Alerta'] }))
  };

  /* --- Lembretes --- */
  const L = out.lembretes;
  lerTabela_('PMOC').filter(x => x['Situação'] === 'Vencido' || x['Situação'] === 'Vence em breve')
    .forEach(x => L.push({ tipo: x['Situação'] === 'Vencido' ? 'vermelho' : 'ambar', icone: 'check', titulo: 'PMOC ' + (x['Situação'] === 'Vencido' ? 'vencido' : 'vence em breve'), texto: x['Equipamento'] + (x['Próxima'] ? ' · ' + x['Próxima'] : ''), ir: 'pmoc' }));
  lerTabela_('ESTOQUE').filter(x => x['Situação'] === 'Repor')
    .forEach(x => L.push({ tipo: 'ambar', icone: 'caixa', titulo: 'Repor estoque', texto: x['Item'] + ' · ' + x['Quantidade'] + ' ' + x['Unidade'], ir: 'estoque' }));
  s.filter(x => normalizar_(x['Situação']) === 'ORCAMENTO' && (d => d && (hoje - d) > 7 * 864e5)(dataDe_(x['Aberto em'])))
    .forEach(x => L.push({ tipo: '', icone: 'chave', titulo: 'Orçamento sem resposta', texto: x['Cliente'] + ' · aberto em ' + Utilities.formatDate(dataDe_(x['Aberto em']), CFG.FUSO, 'dd/MM'), ir: 'servicos' }));
  if (tem_(u, 'orcamentos')) {
    lerTabela_('ORCAMENTOS').filter(x => /Vence|Vencido/.test(x['Alerta'] || '') && (d => !d || (hoje - d) < 15 * 864e5)(dataDe_(x['Válido até']))).forEach(x => {
      const venc = x['Alerta'] === 'Vencido';
      L.push({ tipo: venc ? '' : 'ambar', icone: 'orcamento', titulo: venc ? 'Orçamento venceu sem resposta' : 'Orçamento ' + String(x['Alerta']).toLowerCase(), texto: x['Cliente'] + ' · ' + x._id, valor: num_(x['Total']), fin: true, ir: 'orcamentos' });
    });
  }
  if (tem_(u, 'clientes')) {
    lerTabela_('CONTRATOS').filter(x => x['Alerta']).forEach(x => L.push({ tipo: x['Alerta'] === 'Vencido' ? 'vermelho' : 'ambar', icone: 'prancheta',
      titulo: 'Contrato ' + String(x['Alerta']).toLowerCase(), texto: x['Cliente'] + ' · ' + x['Tipo'] + (x['Fim'] ? ' · até ' + Utilities.formatDate(dataDe_(x['Fim']), CFG.FUSO, 'dd/MM/yyyy') : ''), ir: 'clientes' }));
  }
  if (tem_(u, 'fixas')) {
    lerTabela_('FIXAS').filter(x => !x[MESES[hoje.getMonth()]] && Number(x['Dia'])).forEach(x => {
      const dia = Number(x['Dia']), falta = dia - hoje.getDate();
      if (falta <= 5) L.push({ tipo: falta < 0 ? 'vermelho' : 'ambar', icone: 'repetir', titulo: falta < 0 ? 'Conta fixa atrasada' : falta === 0 ? 'Conta fixa vence hoje' : 'Conta fixa vence em ' + falta + (falta === 1 ? ' dia' : ' dias'),
        texto: x['Despesa fixa'] + ' · dia ' + dia, valor: num_(x['Valor']), fin: true, ir: 'fixas' });
    });
  }
  if (tem_(u, 'financeiro')) {
    lerTabela_('MOVIMENTO').filter(x => !x['Pago?'] && (d => d && d <= em7)(dataDe_(x['Data']))).forEach(x => {
      const ent = x['Entrada ou saída'] === 'Entrada', atras = dataDe_(x['Data']) < hoje;
      L.push({ tipo: atras ? 'vermelho' : 'ambar', icone: 'dinheiro', titulo: (ent ? 'A receber' : 'A pagar') + (atras ? ' (atrasado)' : ''), texto: (x['Descrição'] || x['Categoria']) + ' · ' + Utilities.formatDate(dataDe_(x['Data']), CFG.FUSO, 'dd/MM'), valor: num_(x['Valor']), fin: true, ir: 'financeiro' });
    });
  }
  const peso = { vermelho: 0, ambar: 1, '': 2 };
  L.sort((a, b) => peso[a.tipo] - peso[b.tipo]);

  /* --- Financeiro, estilo aplicativo de banco (só para quem tem o módulo) --- */
  if (tem_(u, 'financeiro')) {
    const f = planilha_('FINANCEIRO').getSheetByName('PAINEL');
    const mov = lerTabela_('MOVIMENTO').filter(x => x['Categoria'] !== 'Saldo inicial');
    const fixas = tem_(u, 'fixas') ? lerTabela_('FIXAS') : [];
    const noMes = x => noMesD(dataDe_(x['Data']));
    const soma = l => l.reduce((t, x) => t + num_(x['Valor']), 0);
    const pagos = mov.filter(x => x['Pago?']), abertos = mov.filter(x => !x['Pago?']);
    const fixasFalta = fixas.filter(x => !x[MESES[hoje.getMonth()]] && !exemplo_(x['Despesa fixa']));
    const proximos = abertos.map(x => ({ id: x._id, tab: 'MOVIMENTO', entrada: x['Entrada ou saída'] === 'Entrada', desc: x['Descrição'] || x['Categoria'], data: x['Data'], valor: num_(x['Valor']) }))
      .concat(fixasFalta.map(x => ({ id: x._id, tab: 'FIXAS', entrada: false, desc: x['Despesa fixa'] + ' (fixa)', data: Number(x['Dia']) ? fmtData_(new Date(hoje.getFullYear(), hoje.getMonth(), Number(x['Dia']))) : '', valor: num_(x['Valor']) })))
      .sort((a, b) => String(a.data || '9').localeCompare(String(b.data || '9'))).slice(0, 8);
    const extrato = pagos.slice().sort((a, b) => String(b['Data']).localeCompare(String(a['Data']))).slice(0, 8)
      .map(x => ({ id: x._id, entrada: x['Entrada ou saída'] === 'Entrada', desc: x['Descrição'] || x['Categoria'], cat: x['Categoria'], data: x['Data'], valor: num_(x['Valor']), por: x['Confirmado por'] }));
    out.financeiro = {
      saldo: num_(f.getRange('E6').getValue()), reserva: num_(f.getRange('D10').getValue()),
      entrouMes: soma(pagos.filter(x => noMes(x) && x['Entrada ou saída'] === 'Entrada')),
      saiuMes: soma(pagos.filter(x => noMes(x) && x['Entrada ou saída'] === 'Saída')) + soma(fixas.filter(x => x[MESES[hoje.getMonth()]])),
      aReceber: soma(abertos.filter(x => x['Entrada ou saída'] === 'Entrada')),
      aPagar: soma(abertos.filter(x => x['Entrada ou saída'] === 'Saída')) + soma(fixasFalta),
      servicosSemPagamento: concl.filter(x => normalizar_(x['Pago?']) !== 'SIM' && !exemplo_(x['Cliente'])).reduce((t, x) => t + num_(x['Valor']), 0),
      proximos: proximos, extrato: extrato
    };
  }
  return out;
}

/** ===================== MEU PONTO ===================== */
const MARCAS = ['Entrada', 'Saída almoço', 'Volta almoço', 'Saída'];
function nomePonto_(u) { return String(u.funcionario || u.nome || '').trim(); }

function pontoHoje_(u) {
  const nome = nomePonto_(u), hojeS = fmtData_(hoje_()), mesS = hojeS.slice(0, 7);
  const cadastrado = lerTabela_('FUNCIONARIOS').some(f => normalizar_(f['Nome']) === normalizar_(nome));
  const meus = lerTabela_('PONTO').filter(x => normalizar_(x['Funcionário']) === normalizar_(nome));
  const hoje = meus.find(x => x['Data'] === hojeS) || null;
  const doMes = meus.filter(x => String(x['Data']).slice(0, 7) === mesS);
  const prox = hoje ? MARCAS.find(m => !hoje[m]) : 'Entrada';
  return {
    nome: nome, cadastrado: cadastrado, hoje: hoje, proxima: prox || null,
    mes: { dias: doMes.filter(x => minutos_(x['Horas trabalhadas']) > 0).length,
      horas: hhmm_(doMes.reduce((a, x) => a + minutos_(x['Horas trabalhadas']), 0)),
      extras: hhmm_(doMes.reduce((a, x) => a + minutos_(x['Horas extras']), 0)),
      faltas: doMes.filter(x => x['Situação'] === 'Falta').length },
    ultimos: meus.sort((a, b) => String(b['Data']).localeCompare(String(a['Data']))).slice(0, 10)
  };
}

function pontoRegistrar_(u) {
  const nome = nomePonto_(u);
  const info = pontoHoje_(u);
  if (!info.cadastrado) throw erroUsuario_('Seu usuário não está ligado a um funcionário. Peça ao administrador para escolher seu nome em Usuários.');
  if (!info.proxima) throw erroUsuario_('Os quatro horários de hoje já foram registrados.');
  const agora = Utilities.formatDate(new Date(), CFG.FUSO, 'HH:mm');
  const valores = {}; valores[info.proxima] = agora;
  if (!info.hoje) { valores['Data'] = fmtData_(hoje_()); valores['Funcionário'] = nome; valores['Situação'] = 'Normal'; }
  gravar_(u, { tabela: 'PONTO', id: info.hoje ? info.hoje._id : '', valores: valores }, true);
  log_('PONTO', u.login, info.proxima + ' ' + agora);
  return { marcado: info.proxima, hora: agora };
}

/** ===================== CONTROLE DE FUNCIONÁRIOS ===================== */
function valorHoraExtra_(f) {
  const proprio = num_(f['Valor hora extra']);
  if (proprio) return proprio;
  const hora = num_(f['Valor da hora']);
  return hora ? Math.round(hora * 1.5 * 100) / 100 : 0;
}
function ativos_() { return lerTabela_('FUNCIONARIOS').filter(f => normalizar_(f['Ativo?']) !== 'NAO'); }

function presencaDia_(u, d) {
  const data = d.data && dataDe_(d.data) ? d.data : fmtData_(hoje_());
  const regs = lerTabela_('PRESENCA').filter(x => x['Data'] === data);
  const lista = ativos_().map(f => {
    const r = regs.find(x => normalizar_(x['Funcionário']) === normalizar_(f['Nome'])) || null;
    return { nome: f['Nome'], funcao: f['Função'], forma: f['Forma de pagamento'] || 'Mensal', diaria: num_(f['Valor da diária']), vhe: valorHoraExtra_(f),
      reg: r ? { id: r._id, presenca: r['Presença'], he: r['Horas extras'], obs: r['Observação'], por: r['Marcado por'] } : null };
  }).sort((a, b) => (a.forma === 'Diária' ? 0 : 1) - (b.forma === 'Diária' ? 0 : 1) || a.nome.localeCompare(b.nome, 'pt-BR'));
  return { data: data, lista: lista };
}

function presencaSalvar_(u, d) {
  const data = d.data && dataDe_(d.data) ? d.data : '';
  if (!data) throw erroUsuario_('Data inválida.');
  const base = presencaDia_(u, { data: data }).lista;
  let gravados = 0;
  (d.itens || []).forEach(it => {
    const f = base.find(x => x.nome === it.nome);
    if (!f) return;
    const pres = ['Presente', 'Meia diária', 'Falta', 'Folga'].indexOf(it.presenca) >= 0 ? it.presenca : '';
    if (!pres) {
      if (f.reg) { limpar_(u, { tabela: 'PRESENCA', id: f.reg.id }); gravados++; }
      return;
    }
    const he = num_(it.he);
    if (he < 0 || he > 16) throw erroUsuario_('Horas extras inválidas para ' + f.nome + '.');
    const mudou = !f.reg || f.reg.presenca !== pres || num_(f.reg.he) !== he || String(f.reg.obs || '') !== String(it.obs || '');
    if (!mudou) return;
    gravar_(u, { tabela: 'PRESENCA', id: f.reg ? f.reg.id : '', valores: {
      'Data': data, 'Funcionário': f.nome, 'Presença': pres, 'Horas extras': he || '',
      'Valor da diária': f.forma === 'Diária' ? f.diaria : 0, 'Valor hora extra': f.vhe,
      'Observação': String(it.obs || '').slice(0, 300), 'Marcado por': (u.nome || u.login) + ' · ' + agoraTxt_() } }, true);
    gravados++;
  });
  log_('PRESENCA', u.login, data + ' · ' + gravados + ' alteração(ões)');
  return { gravados: gravados };
}

function controleResumo_(u, d) {
  const mes = /^\d{4}-\d{2}$/.test(String(d.mes || '')) ? d.mes : fmtData_(hoje_()).slice(0, 7);
  const pres = lerTabela_('PRESENCA').filter(x => String(x['Data']).slice(0, 7) === mes);
  const ponto = lerTabela_('PONTO').filter(x => String(x['Data']).slice(0, 7) === mes);
  const nomes = ativos_().map(f => f['Nome']);
  pres.concat(ponto).forEach(x => { if (nomes.indexOf(x['Funcionário']) < 0) nomes.push(x['Funcionário']); });
  const funcs = lerTabela_('FUNCIONARIOS');
  const linhas = nomes.map(n => {
    const p = pres.filter(x => x['Funcionário'] === n), q = ponto.filter(x => x['Funcionário'] === n);
    const f = funcs.find(x => x['Nome'] === n) || {};
    const total = p.reduce((t, x) => t + (x['Presença'] === 'Presente' ? num_(x['Valor da diária']) : x['Presença'] === 'Meia diária' ? num_(x['Valor da diária']) / 2 : 0) + num_(x['Horas extras']) * num_(x['Valor hora extra']), 0);
    return { nome: n, forma: f['Forma de pagamento'] || '', salario: num_(f['Salário base']),
      presentes: p.filter(x => x['Presença'] === 'Presente').length, meias: p.filter(x => x['Presença'] === 'Meia diária').length,
      faltas: p.filter(x => x['Presença'] === 'Falta').length + q.filter(x => x['Situação'] === 'Falta').length,
      he: p.reduce((t, x) => t + num_(x['Horas extras']), 0), heValor: p.reduce((t, x) => t + num_(x['Horas extras']) * num_(x['Valor hora extra']), 0),
      totalDiarias: Math.round(total * 100) / 100,
      pontoDias: q.filter(x => minutos_(x['Horas trabalhadas']) > 0).length,
      pontoHoras: hhmm_(q.reduce((t, x) => t + minutos_(x['Horas trabalhadas']), 0)),
      pontoExtras: hhmm_(q.reduce((t, x) => t + minutos_(x['Horas extras']), 0)) };
  }).filter(l => !exemplo_(l.nome) || l.presentes || l.pontoDias);
  return { mes: mes, linhas: linhas, total: linhas.reduce((t, l) => t + l.totalDiarias, 0) };
}

/** ===================== MINHA AGENDA (técnico) ===================== */
function nomeTecnico_(u) { return String(u.tecnico || u.funcionario || u.nome || '').trim(); }
function servicoDoUsuario_(u, id) {
  const s = lerTabela_('SERVICOS').find(x => x._id === String(id));
  if (!s) throw erroUsuario_('Serviço não encontrado.');
  if (!tem_(u, 'servicos') && normalizar_(s['Técnico']) !== normalizar_(nomeTecnico_(u)))
    throw erroUsuario_('Este serviço não está na sua agenda.');
  return s;
}
/** Contratos que têm equipamento ligado (ou são do tipo PMOC): o serviço mostra o botão "Checklist PMOC". */
function contratosPmoc_() {
  const m = {};
  lerTabela_('CONTRATOS').forEach(c => { if (normalizar_(c['Tipo']).indexOf('PMOC') >= 0) m[c._id] = 1; });
  lerTabela_('EQUIPAMENTOS').forEach(e => { if (e['Contrato']) m[e['Contrato']] = 1; });
  return m;
}
function clientesPorNome_() {
  const cli = {};
  lerTabela_('CLIENTES').forEach(c => { cli[c['Nome / razão social']] = { id: c._id, tel: c['Telefone'], email: c['E-mail'], doc: c['CPF / CNPJ'], genero: c['Gênero'], pessoa: c['Pessoa'],
    end: [c['Endereço'], c['Bairro'], c['Cidade']].filter(Boolean).join(', '), contato: c['Contato no local'] }; });
  return cli;
}

function agenda_(u) {
  const nome = normalizar_(nomeTecnico_(u));
  const meus = lerTabela_('SERVICOS').filter(x => normalizar_(x['Técnico']) === nome && normalizar_(x['Situação']) !== 'CANCELADO');
  const cli = clientesPorNome_();
  const pm = contratosPmoc_();
  const enr = x => Object.assign({}, x, { _cliente: cli[x['Cliente']] || {}, _pmoc: !!pm[x['Contrato']] });
  return {
    tecnico: nomeTecnico_(u),
    pendentes: meus.filter(x => normalizar_(x['Situação']) !== 'CONCLUIDO')
      .sort((a, b) => String(a['Agendado para'] || '9').localeCompare(String(b['Agendado para'] || '9'))).map(enr),
    concluidos: meus.filter(x => normalizar_(x['Situação']) === 'CONCLUIDO')
      .sort((a, b) => String(b['Concluído em']).localeCompare(String(a['Concluído em']))).slice(0, 15).map(enr)
  };
}

function agendaAcao_(u, d) {
  const s = servicoDoUsuario_(u, d.id);
  const v = {}, hora = Utilities.formatDate(new Date(), CFG.FUSO, 'dd/MM HH:mm'), quem = nomeTecnico_(u);
  const linhas = [];
  const fechado = normalizar_(s['Situação']) === 'CONCLUIDO';
  if (d.acao === 'iniciar') { v['Situação'] = 'Em andamento'; linhas.push(hora + ' Início do serviço (' + quem + ')'); }
  else if (d.acao === 'concluir') {
    if (fechado) throw erroUsuario_('Este serviço já está concluído.');
    v['Situação'] = 'Concluído'; v['Concluído em'] = fmtData_(hoje_());
    if (d.obs) linhas.push(hora + ' ' + quem + ': ' + String(d.obs).slice(0, 1000));
    linhas.push(hora + ' Fim do serviço (' + quem + ')');
  }
  else if (d.acao === 'reabrir') { v['Situação'] = 'Em andamento'; v['Concluído em'] = ''; linhas.push(hora + ' Reaberto (' + quem + ')'); }
  else if (d.acao === 'anotar') {
    if (!String(d.obs || '').trim()) throw erroUsuario_('Escreva a anotação.');
    if (fechado) throw erroUsuario_('Serviço concluído. Reabra para anotar.');
    linhas.push(hora + ' ' + quem + ': ' + String(d.obs).slice(0, 1000));
  }
  else throw erroUsuario_('Ação desconhecida.');
  v['Descrição'] = (s['Descrição'] ? s['Descrição'] + '\n' : '') + linhas.join('\n');
  gravar_(u, { tabela: 'SERVICOS', id: s._id, valores: v }, true);
  return true;
}

/** Tudo que a tela de detalhe do serviço precisa. */
function servicoInfo_(u, d) {
  const s = servicoDoUsuario_(u, d.id);
  return Object.assign({}, s, { _cliente: clientesPorNome_()[s['Cliente']] || {},
    _materiais: lerTabela_('MATERIAIS').filter(x => x['Nº OS'] === s._id).length,
    _podeEditar: tem_(u, 'servicos'), _pmoc: !!contratosPmoc_()[s['Contrato']] });
}

/** ===================== FOTOS, ASSINATURA E COMPROVANTE ===================== */
/** Alvo dos arquivos: serviço (padrão), equipamento, contrato ou lançamento financeiro. */
const ALVOS = {
  equipamento: { mod: ['equipamentos'], tabela: 'EQUIPAMENTOS', coluna: 'Fotos', raiz: 'fotos', sub: 'Equipamentos', desc: e => e['Cliente'] + ' · ' + (e['Local / setor'] || '') },
  contrato:    { mod: ['clientes'], tabela: 'CONTRATOS', coluna: 'Arquivos', raiz: 'docs', sub: 'Contratos', desc: e => e['Cliente'] + ' · ' + e['Tipo'] },
  movimento:   { mod: ['financeiro'], tabela: 'MOVIMENTO', coluna: 'Comprovante', raiz: 'fin', sub: 'Comprovantes e recibos', desc: e => (e['Descrição'] || e['Categoria']) + ' · ' + e['Valor'] },
  fixa:        { mod: ['fixas'], tabela: 'FIXAS', coluna: 'Comprovantes', raiz: 'fin', sub: 'Comprovantes e recibos', desc: e => e['Despesa fixa'] },
  reserva:     { mod: ['reserva'], tabela: 'RESERVA', coluna: 'Comprovante', raiz: 'fin', sub: 'Comprovantes e recibos', desc: e => e['Guardei ou tirei'] + ' · ' + e['Valor'] }
};
function alvoFotos_(u, d) {
  const a = ALVOS[d.tipo];
  if (a) {
    if (!a.mod.some(m => tem_(u, m))) throw erroUsuario_('Você não tem acesso a este módulo.');
    const e = lerTabela_(a.tabela).find(x => x._id === String(d.id));
    if (!e) throw erroUsuario_('Registro não encontrado.');
    return { reg: e, tabela: a.tabela, coluna: a.coluna, raiz: a.raiz, sub: a.sub, desc: a.desc(e) };
  }
  const s = servicoDoUsuario_(u, d.id);
  return { reg: s, tabela: 'SERVICOS', coluna: 'Pasta / fotos', raiz: 'fotos', sub: '', desc: String(s['Cliente'] || '') };
}
/** Pastas-raiz no Drive. A do financeiro é a pasta onde está a planilha Financeiro NG. */
function pastaRaiz_(qual) {
  if (qual === 'docs') return DriveApp.getFolderById(idDe_('PASTA_DOCS'));
  if (qual === 'fin') { const p = DriveApp.getFileById(idDe_('FINANCEIRO')).getParents(); return p.hasNext() ? p.next() : DriveApp.getFolderById(idDe_('PASTA_DOCS')); }
  return DriveApp.getFolderById(idDe_('PASTA_FOTOS'));
}
function subpasta_(pai, nome, criar) { const it = pai.getFoldersByName(nome); return it.hasNext() ? it.next() : (criar ? pai.createFolder(nome) : null); }
function pastaDe_(alvo, criar) {
  let raiz = pastaRaiz_(alvo.raiz);
  if (alvo.sub) { raiz = subpasta_(raiz, alvo.sub, criar); if (!raiz) return null; }
  const it = raiz.getFoldersByName(alvo.reg._id);
  if (it.hasNext()) return it.next();
  if (!criar) return null;
  const nova = raiz.createFolder(alvo.reg._id);
  nova.setDescription(alvo.desc);
  return nova;
}
const EXT = { 'image/png': '.png', 'image/jpeg': '.jpg', 'application/pdf': '.pdf', 'image/webp': '.webp' };
function salvarArquivo_(u, d, prefixo) {
  const alvo = alvoFotos_(u, d);
  const mime = EXT[d.mime] ? d.mime : 'image/jpeg';
  const bytes = Utilities.base64Decode(String(d.base64 || '').replace(/^data:[^,]+,/, ''));
  if (!bytes.length) throw erroUsuario_('Arquivo vazio.');
  if (bytes.length > CFG.FOTO_MAX_MB * 1048576) throw erroUsuario_('Arquivo grande demais (máximo ' + CFG.FOTO_MAX_MB + ' MB).');
  const pasta = pastaDe_(alvo, true);
  const nome = prefixo + Utilities.formatDate(new Date(), CFG.FUSO, 'yyyyMMdd-HHmmss') + EXT[mime];
  const arq = pasta.createFile(Utilities.newBlob(bytes, mime, nome));
  arq.setDescription('Enviado por ' + (u.nome || u.login) + (d.legenda ? ' · ' + d.legenda : ''));
  if (!alvo.reg[alvo.coluna]) { const v = {}; v[alvo.coluna] = pasta.getUrl(); gravar_(u, { tabela: alvo.tabela, id: alvo.reg._id, valores: v }, true); }
  log_('ARQUIVO', u.login, alvo.reg._id + ' ' + nome);
  return { s: alvo.reg, arquivo: nome, id: arq.getId() };
}
function fotoEnviar_(u, d) {
  const pref = { antes: 'antes-', depois: 'depois-', comprovante: 'comprovante-', contrato: 'contrato-' }[d.momento] || (/^[A-Z][a-z]{2}$/.test(d.momento || '') ? 'comprovante-' + d.momento + '-' : 'foto-');
  const r = salvarArquivo_(u, d, pref);
  return { id: r.id, arquivo: r.arquivo };
}
function assinaturaEnviar_(u, d) {
  const resp = String(d.responsavel || '').trim().slice(0, 120);
  if (!resp) throw erroUsuario_('Informe o nome de quem assinou.');
  const r = salvarArquivo_(u, Object.assign({}, d, { tipo: 'servico', mime: 'image/png', legenda: 'Assinatura de ' + resp }), 'assinatura-');
  const s = lerTabela_('SERVICOS').find(x => x._id === r.s._id);
  gravar_(u, { tabela: 'SERVICOS', id: s._id, valores: { 'Descrição': (s['Descrição'] ? s['Descrição'] + '\n' : '') +
    Utilities.formatDate(new Date(), CFG.FUSO, 'dd/MM HH:mm') + ' Assinado por ' + resp } }, true);
  return true;
}
function fotosListar_(u, d) {
  const pasta = pastaDe_(alvoFotos_(u, d), false);
  if (!pasta) return [];
  const out = [], fs = pasta.getFiles();
  while (fs.hasNext() && out.length < 40) {
    const f = fs.next();
    let mini = '';
    try { const t = f.getThumbnail(); if (t) mini = 'data:image/png;base64,' + Utilities.base64Encode(t.getBytes()); } catch (e) { }
    const n = f.getName();
    const id = f.getId();
    out.push({ id: id, nome: n, mini: mini, url: 'https://drive.google.com/file/d/' + id + '/view', data: f.getDateCreated().getTime(), pdf: /\.pdf$/i.test(n),
      tipo: /^assinatura/.test(n) ? 'Assinatura' : /^antes/.test(n) ? 'Antes' : /^depois/.test(n) ? 'Depois' : /^Recibo/i.test(n) ? 'Recibo' : /^Or[cç]amento/i.test(n) ? 'Orçamento' :
        /^comprovante-([A-Z][a-z]{2})-/.test(n) ? 'Comprovante ' + n.split('-')[1] : /^comprovante|^Comprovante/i.test(n) ? 'Comprovante' : /^contrato/i.test(n) ? 'Contrato' : /\.pdf$/i.test(n) ? 'Documento' : 'Foto' });
  }
  return out.sort((a, b) => b.data - a.data);
}

/** ===================== MATERIAIS USADOS NO SERVIÇO ===================== */
function itensEstoque_() {
  return lerTabela_('ESTOQUE').filter(x => !exemplo_(x['Item'])).map(x => ({ id: x._id, item: x['Item'], categoria: x['Categoria'] || 'Sem categoria',
    unidade: x['Unidade'], qtd: num_(x['Quantidade']), valor: num_(x['Valor unitário']) }))
    .sort((a, b) => a.categoria.localeCompare(b.categoria, 'pt-BR') || a.item.localeCompare(b.item, 'pt-BR'));
}
function materiaisListar_(u, d) {
  const s = servicoDoUsuario_(u, d.os);
  return { os: s._id, fechado: normalizar_(s['Situação']) === 'CONCLUIDO',
    usados: lerTabela_('MATERIAIS').filter(x => x['Nº OS'] === s._id).map(x => ({ id: x._id, item: x['Item'], qtd: x['Quantidade'], unidade: x['Unidade'], total: num_(x['Total']), por: x['Lançado por'] })),
    estoque: itensEstoque_() };
}
function ajustarEstoque_(u, idItem, delta) {
  const it = lerTabela_('ESTOQUE').find(x => x._id === String(idItem));
  if (!it) return null;
  gravar_(u, { tabela: 'ESTOQUE', id: it._id, valores: { 'Quantidade': Math.round((num_(it['Quantidade']) + delta) * 1000) / 1000 } }, true);
  return it;
}
function materialAdicionar_(u, d) {
  const s = servicoDoUsuario_(u, d.os);
  if (normalizar_(s['Situação']) === 'CONCLUIDO') throw erroUsuario_('Serviço concluído. Reabra para lançar material.');
  const qtd = num_(d.qtd);
  if (!(qtd > 0) || qtd > 10000) throw erroUsuario_('Informe a quantidade.');
  const it = lerTabela_('ESTOQUE').find(x => x._id === String(d.item));
  if (!it) throw erroUsuario_('Item não encontrado no estoque.');
  gravar_(u, { tabela: 'MATERIAIS', id: '', valores: { 'Data': fmtData_(hoje_()), 'Nº OS': s._id, 'Item': it['Item'], 'Quantidade': qtd,
    'Unidade': it['Unidade'], 'Valor unitário': num_(it['Valor unitário']), 'Lançado por': u.nome || u.login, 'ID item': it._id } }, true);
  ajustarEstoque_(u, it._id, -qtd);
  const sobra = num_(it['Quantidade']) - qtd;
  return { aviso: sobra < 0 ? 'Atenção: o estoque de ' + it['Item'] + ' ficou negativo (' + sobra + ').' : '' };
}
function materialRemover_(u, d) {
  const m = lerTabela_('MATERIAIS').find(x => x._id === String(d.id));
  if (!m) throw erroUsuario_('Lançamento não encontrado.');
  const s = servicoDoUsuario_(u, m['Nº OS']);
  if (normalizar_(s['Situação']) === 'CONCLUIDO') throw erroUsuario_('Serviço concluído. Reabra para mudar os materiais.');
  if (m['ID item']) ajustarEstoque_(u, m['ID item'], num_(m['Quantidade']));
  limpar_(u, { tabela: 'MATERIAIS', id: m._id });
  return true;
}

/** ===================== FINANCEIRO ===================== */
function movimentoPagar_(u, d) {
  const m = lerTabela_('MOVIMENTO').find(x => x._id === String(d.id));
  if (!m) throw erroUsuario_('Lançamento não encontrado.');
  if (m['Pago?']) throw erroUsuario_('Este lançamento já estava confirmado.');
  gravar_(u, { tabela: 'MOVIMENTO', id: m._id, valores: { 'Pago?': true, 'Confirmado por': u.nome || u.login, 'Confirmado em': agoraTxt_() } }, true);
  log_('PAGAMENTO_CONFIRMADO', u.login, m._id + ' ' + m['Valor']);
  return true;
}
function fixaPagarMes_(u, d) {
  const f = lerTabela_('FIXAS').find(x => x._id === String(d.id));
  if (!f) throw erroUsuario_('Despesa não encontrada.');
  const mes = MESES[hoje_().getMonth()];
  if (f[mes]) throw erroUsuario_(mes + ' já estava marcado como pago.');
  const v = {}; v[mes] = true;
  gravar_(u, { tabela: 'FIXAS', id: f._id, valores: v }, true);
  return { mes: mes };
}

/** ===================== CONTATOS DO SITE E NOTIFICAÇÕES ===================== */
function abaContatos_() { return abaSistema_('CONTATOS DO SITE', ['data', 'tipo', 'nome', 'telefone', 'servico', 'mensagem', 'botao', 'visto']); }
function lerContatos_(max) {
  const aba = abaContatos_(), n = aba.getLastRow();
  if (n < 2) return [];
  const ini = Math.max(2, n - (max || 200) + 1);
  return aba.getRange(ini, 1, n - ini + 1, 8).getValues().map((r, i) => ({ linha: ini + i,
    data: r[0] instanceof Date ? Utilities.formatDate(r[0], CFG.FUSO, 'dd/MM/yyyy HH:mm') : String(r[0]), tipo: String(r[1]), nome: String(r[2]),
    tel: String(r[3]), servico: String(r[4]), msg: String(r[5]), botao: String(r[6]), visto: r[7] === true || String(r[7]).toUpperCase() === 'TRUE' })).reverse();
}
function contatosListar_() { return lerContatos_(300); }
function contatoVisto_(u, d) {
  const aba = abaContatos_();
  const linhas = d.todos ? lerContatos_(300).filter(c => !c.visto).map(c => c.linha) : [Number(d.linha)];
  linhas.forEach(l => { if (l >= 2 && l <= aba.getLastRow()) aba.getRange(l, 8).setValue(d.visto !== false); });
  return true;
}
function notificacoes_(u) {
  const itens = [];
  if (tem_(u, 'contatos') && CFG.CONTATOS_SITE) {
    lerContatos_(60).filter(c => !c.visto).slice(0, 10).forEach(c => itens.push({ icone: 'sino', titulo: 'Contato pelo site · ' + c.tipo,
      texto: [c.nome, c.servico, c.botao].filter(Boolean).join(' · ') || 'Alguém tocou no botão do site', quando: c.data, ir: 'contatos' }));
  }
  return { total: itens.length, itens: itens };
}

/** ===================== USUÁRIOS E PERFIS (administração) ===================== */
function usuariosListar_() {
  const funcs = lerTabela_('FUNCIONARIOS').filter(f => !exemplo_(f['Nome']));
  return {
    usuarios: lerUsuarios_().map(x => ({ login: String(x.login), nome: String(x.nome), email: String(x.email), perfil: String(x.perfil),
      extras: String(x.modulos_extras || '').split(',').map(s => s.trim()).filter(Boolean).map(m => MODULOS_ANTIGOS[m] || m), tecnico: String(x.tecnico || ''),
      funcionario: String(x.funcionario || ''), ativo: ativo_(x),
      ultimo: x.ultimo_acesso instanceof Date ? Utilities.formatDate(x.ultimo_acesso, CFG.FUSO, 'dd/MM/yyyy HH:mm') : '' })),
    perfis: lerPerfis_().map(p => ({ perfil: p.perfil, descricao: p.descricao, modulos: p.modulos.map(m => MODULOS_ANTIGOS[m] || m) })),
    modulos: Object.keys(MODULOS).map(m => ({ id: m, nome: MODULOS[m].nome, grupo: MODULOS[m].grupo, icone: MODULOS[m].icone })),
    tecnicos: tecnicos_(),
    funcionarios: funcs.map(f => ({ nome: f['Nome'], tecnico: normalizar_(f['Técnico de campo?']) === 'SIM', ativo: normalizar_(f['Ativo?']) !== 'NAO', funcao: f['Função'] }))
  };
}

function usuarioSalvar_(u, d) {
  const login = String(d.login || '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,30}$/.test(login)) throw erroUsuario_('Login: de 3 a 30 letras minúsculas, números, ponto ou traço, sem espaço.');
  if (!String(d.nome || '').trim()) throw erroUsuario_('Informe o nome.');
  if (!lerPerfis_().some(p => p.perfil === d.perfil)) throw erroUsuario_('Escolha um perfil.');
  const extras = (d.extras || []).filter(m => MODULOS[m]).join(',');
  const func = lerTabela_('FUNCIONARIOS').find(f => f['Nome'] === d.funcionario) || null;
  if (d.funcionario && !func) throw erroUsuario_('Funcionário não encontrado.');
  const perf = lerPerfis_().find(p => p.perfil === d.perfil) || { modulos: [] };
  const temAgenda = perf.modulos.indexOf('*') >= 0 || perf.modulos.indexOf('agenda') >= 0 || (d.extras || []).indexOf('agenda') >= 0;
  // Técnico = funcionário com a "Minha agenda" liberada. A agenda dele mostra os serviços com o nome dele.
  const tecnico = func && temAgenda ? func['Nome'] : String(d.tecnico || '');
  const r = comTrava_(() => {
    const todos = lerUsuarios_();
    let alvo = todos.find(x => String(x.login).toLowerCase() === login);
    let temp = '', antigo = '';
    if (d.novo) {
      if (alvo) throw erroUsuario_('Já existe um usuário com esse login.');
      temp = senhaTemporaria_();
      const salt = novoSal_();
      alvo = { login: login, salt: salt, hash: hashSenha_(temp, salt), trocar_senha: true, criado_em: new Date(), ultimo_acesso: '' };
    } else if (!alvo) throw erroUsuario_('Usuário não encontrado.');
    else antigo = String(alvo.funcionario || '');
    if (alvo.login === u.login && (d.ativo === false || d.perfil !== u.perfil))
      throw erroUsuario_('Você não pode desativar nem mudar o perfil do seu próprio usuário.');
    Object.assign(alvo, { nome: String(d.nome).trim(), email: String(d.email || '').trim(), perfil: d.perfil, modulos_extras: extras,
      tecnico: tecnico, funcionario: func ? func['Nome'] : '', ativo: d.ativo !== false });
    gravarUsuario_(alvo);
    log_(d.novo ? 'USUARIO_CRIADO' : 'USUARIO_EDITADO', u.login, login);
    return { senhaTemporaria: temp, antigo: antigo };
  });
  // Mostra na planilha de funcionários qual login está ligado a cada pessoa.
  const funcs = lerTabela_('FUNCIONARIOS');
  if (r.antigo && (!func || r.antigo !== func['Nome'])) { const a = funcs.find(f => f['Nome'] === r.antigo); if (a) gravar_(u, { tabela: 'FUNCIONARIOS', id: a._id, valores: { 'Login no sistema': '' } }, true); }
  if (func) gravar_(u, { tabela: 'FUNCIONARIOS', id: func._id, valores: { 'Login no sistema': login + (d.ativo === false ? ' (inativo)' : '') } }, true);
  if (func && temAgenda && d.ativo !== false) sincronizarTecnico_(func['Nome']);
  return { senhaTemporaria: r.senhaTemporaria };
}

function usuarioSenha_(u, d) {
  return comTrava_(() => {
    const alvo = lerUsuarios_().find(x => String(x.login) === String(d.login));
    if (!alvo) throw erroUsuario_('Usuário não encontrado.');
    const temp = senhaTemporaria_();
    alvo.salt = novoSal_(); alvo.hash = hashSenha_(temp, alvo.salt); alvo.trocar_senha = true;
    gravarUsuario_(alvo);
    CacheService.getScriptCache().remove('TENT_' + normalizar_(alvo.login).replace(/\s/g, ''));
    log_('SENHA_ZERADA', u.login, alvo.login);
    return { senhaTemporaria: temp };
  });
}

function perfisListar_() { return usuariosListar_(); }

function perfilSalvar_(u, d) {
  const nome = String(d.perfil || '').trim();
  if (!nome) throw erroUsuario_('Informe o nome do perfil.');
  let mods = (d.modulos || []).filter(m => MODULOS[m] || m === '*');
  return comTrava_(() => {
    const aba = planilha_('SISTEMA').getSheetByName('PERFIS');
    const perfis = lerPerfis_();
    const p = perfis.find(x => normalizar_(x.perfil) === normalizar_(nome));
    if (p && p.modulos.indexOf('*') >= 0) mods = ['*'];       // o perfil de acesso total continua total
    const linha = p ? p._linha : aba.getLastRow() + 1;
    if (!p && !d.novo) throw erroUsuario_('Perfil não encontrado.');
    if (p && d.novo) throw erroUsuario_('Já existe um perfil com esse nome.');
    aba.getRange(linha, 1, 1, 3).setValues([[nome, String(d.descricao || ''), mods.join(',')]]);
    _perfis = null;
    log_(d.novo ? 'PERFIL_CRIADO' : 'PERFIL_EDITADO', u.login, nome + ': ' + mods.join(','));
    return true;
  });
}

/** Registro: 'log' = eventos importantes e erros · 'req' = todas as requisições. */
function logListar_(u, d) {
  const req = d && d.tipo === 'req';
  if (req) { try { descarregarRequisicoes_(); } catch (e) { } }
  const aba = req ? abaSistema_('REQUISIÇÕES', ['data', 'usuario', 'acao', 'detalhe', 'ms', 'resultado']) : planilha_('SISTEMA').getSheetByName('LOG');
  const n = aba.getLastRow(), larg = req ? 6 : 4;
  if (n < 2) return [];
  const ini = Math.max(2, n - 199);
  return aba.getRange(ini, 1, n - ini + 1, larg).getValues().reverse()
    .map(r => [r[0] instanceof Date ? Utilities.formatDate(r[0], CFG.FUSO, 'dd/MM HH:mm:ss') : String(r[0])].concat(r.slice(1).map(x => String(x).slice(0, 220))));
}

/* ===== Pmoc.gs ===== */
/** ===================== PMOC (Plano de Manutenção, Operação e Controle) =====================
 * Como funciona:
 *  - Aba TIPOS DE EQUIPAMENTO: cada tipo diz qual checklist usa (Split, Piso teto, Fan coil, Chiller…).
 *  - Aba CHECKLIST PMOC: os itens de cada checklist, com a periodicidade (Mensal, Bimestral, Trimestral,
 *    Semestral, Anual). Pode editar à vontade na planilha ou no sistema (PMOC > Checklists).
 *  - Equipamento ligado a um contrato (coluna "Contrato" em EQUIPAMENTOS) entra no PMOC desse contrato.
 *  - Cada mês o sistema mostra só os itens que vencem naquele mês, contando a partir do início do contrato.
 *  - O que o técnico marca vai para a aba REGISTROS PMOC (uma linha por item). Dali saem os relatórios.
 */
const PERIODOS_PMOC = { 'Mensal': 1, 'Bimestral': 2, 'Trimestral': 3, 'Semestral': 6, 'Anual': 12 };
const CAB_REG = ['ID', 'Data', 'Contrato', 'Cliente', 'ID equipamento', 'Equipamento', 'Checklist', 'Mês de referência', 'Grupo', 'Item', 'Periodicidade', 'Resultado', 'Medição', 'Observação', 'Técnico', 'OS'];
const MESES_PT = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];

function mesRef_(s) { const m = String(s || '').match(/^(\d{4})-(\d{2})/); return m ? m[1] + '-' + m[2] : Utilities.formatDate(new Date(), CFG.FUSO, 'yyyy-MM'); }
function mesTxt_(ref) { const p = ref.split('-'); return MESES_PT[+p[1] - 1] + ' de ' + p[0]; }
function mesesEntre_(inicio, ref) {
  const a = String(inicio || '').match(/^(\d{4})-(\d{2})/); if (!a) return 0;
  const b = ref.split('-'); return (+b[0] - +a[1]) * 12 + (+b[1] - +a[2]);
}
/** Item vence no mês k (0 = mês de início) se k for múltiplo da periodicidade. */
function venceNoMes_(per, k) { const n = PERIODOS_PMOC[per] || 1; return k >= 0 && k % n === 0; }

function checklistDoTipo_() {
  const m = {}; lerTabela_('TIPOS_EQ').forEach(t => { m[normalizar_(t['Tipo de equipamento'])] = t['Checklist PMOC'] || ''; });
  return tipo => m[normalizar_(tipo)] || 'Split';
}
function itensChecklist_() {
  const por = {};
  lerTabela_('CHECKLIST').filter(x => normalizar_(x['Ativo?']) !== 'NAO')
    .sort((a, b) => (num_(a['Ordem']) || 9999) - (num_(b['Ordem']) || 9999))
    .forEach(x => { (por[x['Checklist']] = por[x['Checklist']] || []).push({ id: x._id, grupo: x['Grupo'] || '', item: x['Item'], per: x['Periodicidade'] || 'Mensal', resp: x['Resposta'] === 'Medição' ? 'Medição' : 'OK/NOK/NA', un: x['Unidade'] || '' }); });
  return por;
}
function nomeEquip_(e) { return [e._id, e['Cliente'], e['Local / setor']].filter(Boolean).join(' · '); }
function contratoPmoc_(id) {
  const achado = lerTabela_('CONTRATOS').find(x => x._id === String(id || ''));
  if (!achado) throw erroUsuario_('Contrato não encontrado.');
  const ct = Object.assign({}, achado);
  if (!/^\d{4}-\d{2}/.test(String(ct['Início'] || ''))) { const c = criacaoContrato_(ct); ct['Início'] = c.data; ct._inicioAuto = c.origem; }
  return ct;
}
/** Contrato sem "Início": a conta dos meses do PMOC usa a data de criação do contrato.
 *  Ordem: data do PDF do contrato no Drive > data do orçamento > primeiro registro de PMOC > hoje. */
function criacaoContrato_(ct) {
  const idArq = (String(ct['Documento'] || '').match(/\/d\/([\w-]{10,})/) || [])[1];
  if (idArq) { try { return { data: fmtData_(DriveApp.getFileById(idArq).getDateCreated()), origem: 'criação do PDF do contrato' }; } catch (e) { } }
  if (ct['Orçamento']) { const o = lerTabela_('ORCAMENTOS').find(x => x._id === ct['Orçamento']); if (o && /^\d{4}-\d{2}-\d{2}/.test(String(o['Data']))) return { data: String(o['Data']).slice(0, 10), origem: 'data do orçamento ' + o._id }; }
  const regs = lerRegistros_(r => r['Contrato'] === ct._id).map(r => String(r['Mês de referência'])).filter(m => /^\d{4}-\d{2}$/.test(m)).sort();
  if (regs.length) return { data: regs[0] + '-01', origem: 'primeiro registro de PMOC' };
  return { data: fmtData_(hoje_()), origem: 'hoje (o contrato não tem data nenhuma)' };
}
function equipDoContrato_(id) { return lerTabela_('EQUIPAMENTOS').filter(e => e['Contrato'] === id); }

function abaRegistros_() {
  const ss = planilha_('OPERACAO');
  let a = ss.getSheetByName('REGISTROS PMOC');
  if (!a) { a = ss.insertSheet('REGISTROS PMOC'); a.getRange(1, 1, 1, CAB_REG.length).setValues([CAB_REG]); }
  return a;
}
function lerRegistros_(filtro) {
  const a = abaRegistros_(), n = a.getLastRow();
  if (n < 2) return [];
  const v = a.getRange(1, 1, n, a.getLastColumn ? Math.max(a.getLastColumn(), CAB_REG.length) : CAB_REG.length).getValues();
  const cab = cabecalho_(v[0]), out = [];
  for (let r = 1; r < v.length; r++) {
    const o = { _linha: r + 1 }; CAB_REG.forEach(h => { const x = v[r][cab[h]]; o[h] = x instanceof Date ? fmtData_(x) : (x == null ? '' : x); });
    if (o['Mês de referência'] instanceof Date) o['Mês de referência'] = Utilities.formatDate(o['Mês de referência'], CFG.FUSO, 'yyyy-MM');
    o['Mês de referência'] = String(o['Mês de referência']).slice(0, 7);
    if (o['Contrato'] && (!filtro || filtro(o))) out.push(o);
  }
  return out;
}

/** Ficha PMOC de um contrato: equipamentos do cliente (ligados ou não) e meses já feitos. */
function pmocContrato_(u, d) {
  const ct = contratoPmoc_(d.id), tipoCk = checklistDoTipo_();
  const eqs = lerTabela_('EQUIPAMENTOS').filter(e => e['Cliente'] === ct['Cliente'] || e['Contrato'] === ct._id)
    .map(e => ({ id: e._id, local: e['Local / setor'], tipo: e['Tipo'], marca: e['Marca'], cap: e['Capacidade'], checklist: tipoCk(e['Tipo']), ligado: e['Contrato'] === ct._id, outro: e['Contrato'] && e['Contrato'] !== ct._id ? e['Contrato'] : '' }));
  const feitos = {};
  lerRegistros_(r => r['Contrato'] === ct._id).forEach(r => { feitos[r['Mês de referência']] = (feitos[r['Mês de referência']] || 0) + 1; });
  return { id: ct._id, cliente: ct['Cliente'], tipo: ct['Tipo'], inicio: ct['Início'], inicioAuto: ct._inicioAuto || '', art: ct['ART / TRT'], plano: ct['Plano PMOC'], equipamentos: eqs,
    meses: Object.keys(feitos).sort().reverse().map(m => ({ mes: m, txt: mesTxt_(m), itens: feitos[m] })) };
}

/** Liga/desliga equipamentos do cliente a um contrato e cria a linha de acompanhamento na aba PMOC. */
function pmocVincular_(u, d) {
  const ct = contratoPmoc_(d.id), quer = {};
  (d.equipamentos || []).forEach(id => quer[String(id)] = 1);
  const eqs = lerTabela_('EQUIPAMENTOS'), pm = lerTabela_('PMOC');
  let lig = 0;
  eqs.forEach(e => {
    const deve = !!quer[e._id];
    if (deve && e['Contrato'] !== ct._id) gravar_(u, { tabela: 'EQUIPAMENTOS', id: e._id, valores: { 'Contrato': ct._id } }, true);
    if (!deve && e['Contrato'] === ct._id) gravar_(u, { tabela: 'EQUIPAMENTOS', id: e._id, valores: { 'Contrato': '' } }, true);
    if (deve) {
      lig++;
      const nome = nomeEquip_(e);
      if (!pm.some(p => String(p['Equipamento']).indexOf(e._id + ' ·') === 0 || p['Equipamento'] === e._id))
        gravar_(u, { tabela: 'PMOC', id: '', valores: { 'Equipamento': nome, 'Frequência': 'Mensal', 'Responsável técnico': emp_('Responsável técnico') || nomeTecnico_(u), 'Observações': 'Contrato ' + ct._id } }, true);
    }
  });
  log_('PMOC_VINCULO', u.login, ct._id + ' · ' + lig + ' equip.');
  return { ligados: lig };
}

/** Checklist do mês: só os itens que vencem no mês, já com o que foi marcado antes. */
function pmocChecklist_(u, d) {
  let ctId = d.contrato, mes = d.mes, os = null;
  if (d.os) {
    os = servicoDoUsuario_(u, d.os);
    ctId = ctId || os['Contrato'];
    mes = mes || os['Agendado para'] || os['Concluído em'];
  }
  if (!ctId) throw erroUsuario_('Este serviço não está ligado a um contrato PMOC.');
  const ct = contratoPmoc_(ctId), ref = mesRef_(mes), k = mesesEntre_(ct['Início'], ref);
  const tipoCk = checklistDoTipo_(), itens = itensChecklist_();
  const ja = {};
  lerRegistros_(r => r['Contrato'] === ct._id && r['Mês de referência'] === ref).forEach(r => { ja[r['ID equipamento'] + '|' + r['Item']] = r; });
  const eqs = equipDoContrato_(ct._id);
  if (!eqs.length) throw erroUsuario_('Nenhum equipamento ligado ao contrato ' + ct._id + '. Abra o contrato e marque os aparelhos em "PMOC".');
  return {
    contrato: ct._id, cliente: ct['Cliente'], mes: ref, mesTxt: mesTxt_(ref), k: k, os: os ? os._id : '', tecnico: nomeTecnico_(u),
    antes: k < 0,
    equipamentos: eqs.map(e => {
      const ck = tipoCk(e['Tipo']);
      return { id: e._id, local: e['Local / setor'], tipo: e['Tipo'], marca: e['Marca'], cap: e['Capacidade'], checklist: ck,
        itens: (itens[ck] || []).filter(i => venceNoMes_(i.per, Math.max(k, 0))).map(i => {
          const r = ja[e._id + '|' + i.item] || {};
          return Object.assign({}, i, { resultado: r['Resultado'] || '', medicao: r['Medição'] === '' || r['Medição'] == null ? '' : String(r['Medição']), obs: r['Observação'] || '' });
        }) };
    })
  };
}

/** Grava o checklist do mês (substitui o que havia para os mesmos equipamentos no mesmo mês). */
function pmocRegistrar_(u, d) {
  const base = pmocChecklist_(u, { contrato: d.contrato, mes: d.mes, os: d.os });
  const ref = base.mes, ct = contratoPmoc_(base.contrato), hoje = fmtData_(new Date());
  const env = {}; (d.equipamentos || []).forEach(e => { env[String(e.id)] = {}; (e.itens || []).forEach(i => env[String(e.id)][String(i.id)] = i); });
  const linhas = [], ids = {};
  let nok = 0;
  base.equipamentos.forEach(e => {
    const m = env[e.id]; if (!m) return;
    ids[e.id] = 1;
    e.itens.forEach(i => {
      const x = m[i.id] || {};
      const res = ['OK', 'NOK', 'NA'].indexOf(String(x.resultado || '').toUpperCase()) >= 0 ? String(x.resultado).toUpperCase() : '';
      const med = i.resp === 'Medição' ? String(x.medicao == null ? '' : x.medicao).replace(',', '.').replace(/[^\d.\-]/g, '') : '';
      if (!res && med === '' && !x.obs) return;
      if (res === 'NOK') nok++;
      linhas.push(['', hoje, ct._id, ct['Cliente'], e.id, [e.id, e.local, e.tipo].filter(Boolean).join(' · '), e.checklist, ref, i.grupo, i.item, i.per,
        res || (med !== '' ? 'OK' : ''), med === '' ? '' : Number(med), String(x.obs || '').slice(0, 300), String(d.tecnico || base.tecnico || '').slice(0, 60), base.os || String(d.os || '')]);
    });
  });
  if (!linhas.length) throw erroUsuario_('Marque pelo menos um item.');
  const a = abaRegistros_();
  // apaga o que já existia (mesmo contrato, mês e equipamento), de baixo para cima
  lerRegistros_(r => r['Contrato'] === ct._id && r['Mês de referência'] === ref && ids[r['ID equipamento']])
    .map(r => r._linha).sort((x, y) => y - x)
    .reduce((g, l) => { const u = g[g.length - 1]; if (u && u.ini === l + 1) { u.ini = l; u.n++; } else g.push({ ini: l, n: 1 }); return g; }, [])
    .forEach(b => a.deleteRows(b.ini, b.n));
  const ini = Math.max(a.getLastRow(), 1) + 1;
  const pre = 'REG-' + Utilities.formatDate(new Date(), CFG.FUSO, 'yyMMddHHmmss') + '-';
  linhas.forEach((l, i) => { l[0] = pre + String(i + 1).padStart(3, '0'); });
  a.getRange(ini, 1, linhas.length, CAB_REG.length).setValues(linhas);
  // Atualiza a última manutenção na aba PMOC (o alerta de vencimento continua funcionando)
  lerTabela_('PMOC').forEach(p => {
    const id = Object.keys(ids).find(x => String(p['Equipamento']).indexOf(x + ' ·') === 0 || p['Equipamento'] === x);
    if (id) gravar_(u, { tabela: 'PMOC', id: p._id, valores: { 'Última manutenção': hoje } }, true);
  });
  esquecer_();
  log_('PMOC_REGISTRO', u.login, ct._id + ' · ' + ref + ' · ' + linhas.length + ' itens');
  return { itens: linhas.length, nok: nok, mes: ref, mesTxt: mesTxt_(ref), contrato: ct._id };
}

/** Cabeçalho de identificação (igual ao modelo da NG). */
function identPmoc_(ct, c, eqs) {
  const cap = eqs.map(e => e['Capacidade']).filter(Boolean).join(' + ');
  const area = eqs.reduce((s, e) => s + (num_(e['Área (m²)']) || 0), 0), ocup = eqs.reduce((s, e) => s + (num_(e['Ocupantes']) || 0), 0);
  const L = (a, b) => '<tr><td class="r">' + a + '</td><td>' + (b ? h_(b) : '<span style="color:#9fb5bd">________________</span>') + '</td></tr>';
  return '<h2>1. Identificação do ambiente ou conjunto de ambientes</h2><table>' + L('Cliente', ct['Cliente']) + L('CPF / CNPJ', c.doc) + L('Endereço', c.end) +
    L('Área climatizada total', area ? String(area).replace('.', ',') + ' m²' : '') + L('Ocupantes', ocup ? String(ocup) : '') + L('Equipamentos', eqs.length + ' aparelho(s)' + (cap ? ' · ' + cap : '')) + '</table>' +
    '<h2>2. Responsável técnico</h2><table>' + L('Empresa', emp_('Razão social') + ' · CNPJ ' + emp_('CNPJ')) + L('Responsável técnico', emp_('Responsável técnico')) +
    L('Registro (CFT/CREA)', emp_('Registro do responsável técnico')) + L('ART / TRT', ct['ART / TRT']) + L('Contrato', ct._id + (ct['Início'] ? ' · início ' + dtBR_(ct['Início']) : '') + (ct['Fim'] ? ' · fim ' + dtBR_(ct['Fim']) : '')) + '</table>';
}
function tabEquip_(eqs, tipoCk) {
  return '<table><tr><th>ID</th><th>Local</th><th>Tipo</th><th>Marca</th><th>Capacidade</th><th>Modelo</th><th>Nº série</th><th>Checklist</th></tr>' +
    eqs.map(e => '<tr><td>' + h_(e._id) + '</td><td>' + h_(e['Local / setor']) + '</td><td>' + h_(e['Tipo']) + '</td><td>' + h_(e['Marca']) + '</td><td>' + h_(e['Capacidade']) + '</td><td>' + h_(e['Modelo']) + '</td><td>' + h_(e['Nº de série']) + '</td><td>' + h_(tipoCk(e['Tipo'])) + '</td></tr>').join('') + '</table>';
}

/* ---------- Laudo por equipamento: cada aparelho numa folha, com cabeçalho, dados e assinaturas ---------- */
const ORDEM_PER = ['Mensal', 'Bimestral', 'Trimestral', 'Semestral', 'Anual'];
const PER_PLURAL = { 'Mensal': 'mensais', 'Bimestral': 'bimestrais', 'Trimestral': 'trimestrais', 'Semestral': 'semestrais', 'Anual': 'anuais' };
function linhaPmoc_(a, b) { return '<tr><td class="r">' + a + '</td><td>' + (b ? h_(b) : '<span style="color:#9fb5bd">________________</span>') + '</td></tr>'; }
/** Dados do cliente (como no relatório que a NG já usava: cliente, endereço, responsável, contato). */
function clientePmoc_(ct, c) {
  const v = x => x ? h_(x) : '<span style="color:#9fb5bd">__________</span>';
  const par = (a, x, b, y) => '<tr><td class="r">' + a + '</td><td>' + v(x) + '</td><td class="r">' + b + '</td><td>' + v(y) + '</td></tr>';
  return '<h2>Cliente</h2><table>' + par('Cliente', ct['Cliente'], 'CPF / CNPJ', c.doc) + par('Endereço', c.end, 'Contato', c.tel) +
    par('Responsável no local', c.contato, 'Contrato', ct._id + (ct['ART / TRT'] ? ' · ART/TRT ' + ct['ART / TRT'] : '')) + '</table>';
}
/** Dados do aparelho: equipamento, marca, capacidade, modelo, série, localização. */
function aparelhoPmoc_(e, ck) {
  return '<h2>Equipamento</h2><table><tr><th>Equipamento</th><th>Marca</th><th>Capacidade</th><th>Modelo</th><th>Nº de série</th><th>Localização</th></tr>' +
    '<tr><td>' + h_(e['Tipo'] || '') + '<br><small style="color:#5f717a">' + h_(e._id) + (ck ? ' · checklist ' + h_(ck) : '') + '</small></td><td>' + h_(e['Marca'] || '') + '</td><td>' + h_(e['Capacidade'] || '') + '</td>' +
    '<td>' + h_(e['Modelo'] || '') + '</td><td>' + h_(e['Nº de série'] || '') + '</td><td>' + h_(e['Local / setor'] || '') + '</td></tr></table>';
}
function vistosPmoc_(ct, tecnico) {
  const rt = emp_('Responsável técnico'), reg = emp_('Registro do responsável técnico');
  const col = (nome, papel) => '<td style="width:33%"><div>' + h_(nome || ' ') + '<br><small>' + papel + '</small></div></td>';
  return '<table class="vistos"><tr>' + col(ct['Cliente'], 'CONTRATANTE / RESPONSÁVEL NO LOCAL') + col(tecnico || '', 'TÉCNICO · NG AR CONDICIONADO') +
    col(rt || '', 'RESPONSÁVEL TÉCNICO' + (reg ? ' · ' + h_(reg) : '')) + '</tr></table>';
}

/** Plano PMOC (fica no local, à disposição da fiscalização): 1ª folha com a identificação; depois uma folha por aparelho. */
function pmocPlano_(u, d) {
  const ct = contratoPmoc_(d.id), c = clientesPorNome_()[ct['Cliente']] || {}, eqs = equipDoContrato_(ct._id);
  if (!eqs.length) throw erroUsuario_('Ligue os equipamentos ao contrato antes de gerar o plano.');
  const tipoCk = checklistDoTipo_(), itens = itensChecklist_();
  // 12 meses a partir do início do contrato (ou do mês atual)
  const ini = mesRef_(ct['Início']), p = ini.split('-').map(Number);
  const meses = []; for (let i = 0; i < 12; i++) { const dd = new Date(p[0], p[1] - 1 + i, 1); meses.push({ k: i, txt: MESES_PT[dd.getMonth()].slice(0, 3) + '/' + String(dd.getFullYear()).slice(2) }); }
  const sigla = { 'Mensal': 'M', 'Bimestral': 'B', 'Trimestral': 'T', 'Semestral': 'S', 'Anual': 'A' };
  const calendario = ck => {
    const ls = (itens[ck] || []).slice().sort((a, b) => ORDEM_PER.indexOf(a.per) - ORDEM_PER.indexOf(b.per)); let g = null;
    if (!ls.length) return '<div class="aviso">O checklist "' + h_(ck) + '" não tem itens. Cadastre em PMOC > Checklists.</div>';
    return '<table class="t8 cal"><tr><th>Atividade</th><th>Per.</th>' + meses.map(m => '<th class="m">' + m.txt + '</th>').join('') + '</tr>' +
      ls.map(i => (i.per !== g ? (g = i.per, '<tr><td colspan="' + (meses.length + 2) + '" style="background:#eef6f8;font-weight:bold">Serviços ' + h_(PER_PLURAL[i.per] || i.per) + '</td></tr>') : '') +
        '<tr><td>' + h_(i.item) + (i.un ? ' <small>(' + h_(i.un) + ')</small>' : '') + '</td><td style="text-align:center">' + (sigla[i.per] || '') + '</td>' +
        meses.map(m => '<td class="m">' + (venceNoMes_(i.per, m.k) ? '●' : '') + '</td>').join('') + '</tr>').join('') + '</table>';
  };
  const legenda = '<div class="desc">Periodicidade: M = mensal · B = bimestral · T = trimestral · S = semestral · A = anual. ● = mês em que a atividade é feita.</div>';
  const capa = { titulo: 'Plano de Manutenção, Operação e Controle (PMOC)', subtitulo: ct['Cliente'] + ' · contrato ' + ct._id,
    corpo: identPmoc_(ct, c, eqs) + '<h2>3. Equipamentos do plano</h2>' + tabEquip_(eqs, tipoCk) +
      '<div class="desc">Cada equipamento tem a sua folha a seguir, com o plano de manutenção dele. As atividades seguem a Portaria GM/MS nº 3.523/1998, a Lei nº 13.589/2018 e a Resolução ANVISA RE nº 09/2003. O plano deve ficar disponível no local para a fiscalização.</div>' +
      '<h2>4. Recomendações aos ocupantes</h2><div class="desc">Manter portas e janelas fechadas com o aparelho ligado; não bloquear a saída e o retorno de ar; avisar a contratada sobre ruídos, gotejamento, mau cheiro ou falta de refrigeração; ' +
      'não fumar em ambiente climatizado; manter a renovação de ar prevista no projeto.</div>' + vistosPmoc_(ct, '') };
  const folhas = eqs.map((e, n) => {
    const ck = tipoCk(e['Tipo']);
    return { titulo: 'Plano PMOC · ' + (e['Tipo'] || 'Equipamento') + (e['Local / setor'] ? ' · ' + e['Local / setor'] : ''), subtitulo: ct['Cliente'] + ' · contrato ' + ct._id + ' · equipamento ' + (n + 1) + ' de ' + eqs.length,
      classe: 'lc' + ((itens[ck] || []).length > 20 ? ' denso' : ''), corpo: clientePmoc_(ct, c) + aparelhoPmoc_(e, ck) + '<h2>Plano de manutenção deste equipamento</h2>' + legenda + calendario(ck) + vistosPmoc_(ct, '') };
  });
  const pasta = pastaDe_({ reg: ct, raiz: 'docs', sub: 'Contratos', desc: ct['Cliente'] + ' · ' + ct['Tipo'] }, true);
  const r = salvarPdf_(pasta, 'Plano PMOC ' + ct._id + ' - ' + String(ct['Cliente']).slice(0, 60) + '.pdf', docPaginas_([capa].concat(folhas)));
  const v = { 'Plano PMOC': r.url }; if (!ct['Arquivos']) v['Arquivos'] = pasta.getUrl();
  gravar_(u, { tabela: 'CONTRATOS', id: ct._id, valores: v }, true);
  log_('PMOC_PLANO', u.login, ct._id);
  return { url: r.url, tel: String(c.tel || ''), cliente: ct['Cliente'], equipamentos: eqs.length, trat: saudacao_(ct['Cliente']) };
}

/** Relatório do mês: 1ª folha com o resumo; depois o laudo de cada aparelho (serviços por periodicidade, resultado, observações e vistos). */
function pmocRelatorio_(u, d) {
  const ct = contratoPmoc_(d.id), ref = mesRef_(d.mes), c = clientesPorNome_()[ct['Cliente']] || {};
  const regs = lerRegistros_(r => r['Contrato'] === ct._id && r['Mês de referência'] === ref);
  if (!regs.length) throw erroUsuario_('Nada registrado em ' + mesTxt_(ref) + ' para o contrato ' + ct._id + '.');
  const eqs = equipDoContrato_(ct._id), tipoCk = checklistDoTipo_(), porEq = {};
  regs.forEach(r => (porEq[r['ID equipamento']] = porEq[r['ID equipamento']] || []).push(r));
  const cor = { OK: '#1d7a4b', NOK: '#c0392b', NA: '#8a9aa1' };
  const nok = regs.filter(r => r['Resultado'] === 'NOK');
  const unicos = (ls, k) => Object.keys(ls.reduce((m, r) => (r[k] && (m[k === 'Data' ? dtBR_(r[k]) : r[k]] = 1), m), {})).join(', ');
  const ids = Object.keys(porEq);
  const folhas = ids.map((id, n) => {
    const ls = porEq[id], e = eqs.find(x => x._id === id) || { _id: id, 'Tipo': String(ls[0]['Equipamento'] || id) };
    const ruins = ls.filter(r => r['Resultado'] === 'NOK');
    const porPer = {}; ls.forEach(r => (porPer[r['Periodicidade']] = porPer[r['Periodicidade']] || []).push(r));
    const pers = Object.keys(porPer).sort((a, b) => ORDEM_PER.indexOf(a) - ORDEM_PER.indexOf(b));
    const servicos = pers.map(p => '<h2>Execução dos serviços ' + h_(PER_PLURAL[p] || p) + '</h2><table class="t8"><tr><th>Atividade</th><th style="text-align:center;width:80px">Resultado</th><th style="width:30%">Observação</th></tr>' +
      porPer[p].map(r => '<tr><td>' + h_(r['Item']) + '</td><td style="text-align:center;font-weight:bold;color:' + (cor[r['Resultado']] || '#22343c') + '">' +
        (r['Medição'] !== '' ? h_(String(r['Medição']).replace('.', ',')) : h_(r['Resultado'])) + '</td><td>' + h_(r['Observação']) + '</td></tr>').join('') + '</table>').join('');
    const obs = ls.filter(r => r['Observação']).map(r => r['Item'] + ': ' + r['Observação']);
    const corpo = clientePmoc_(ct, c) + aparelhoPmoc_(e, ls[0]['Checklist'] || tipoCk(e['Tipo'])) +
      '<table><tr><td class="r">Execução</td><td>' + h_(unicos(ls, 'Data')) + ' · técnico ' + h_(unicos(ls, 'Técnico') || '—') + ' · ' + ls.length + ' itens verificados · ' +
        (ruins.length ? '<b style="color:#c0392b">' + ruins.length + ' item(ns) com problema</b>' : '<b style="color:#1d7a4b">tudo em ordem</b>') + '</td></tr></table>' +
      servicos + '<div class="sub" style="margin:2px 0">OK = em ordem · NOK = com problema · NA = não se aplica · números = medição.</div>' +
      '<p style="margin:6px 0 2px"><b>Gera orçamento?</b> &nbsp; (' + (ruins.length ? 'X' : '&nbsp;&nbsp;') + ') Sim &nbsp; ( &nbsp; ) Não</p>' +
      '<p style="margin:4px 0"><b>Obs.:</b> ' + (obs.length ? h_(obs.join('; ')) : '<span style="color:#9fb5bd">______________________________________________________________________</span>') + '</p>' +
      vistosPmoc_(ct, unicos(ls, 'Técnico'));
    return { classe: 'lc' + (ls.length + pers.length * 2 > 26 ? ' denso' : ''), titulo: 'Relatório de manutenção preventiva · ' + mesTxt_(ref), subtitulo: (e['Tipo'] || 'Equipamento') + (e['Local / setor'] ? ' · ' + e['Local / setor'] : '') + ' · equipamento ' + (n + 1) + ' de ' + ids.length, corpo: corpo };
  });
  const faltam = eqs.filter(e => !porEq[e._id]);
  const capa = { titulo: 'Relatório de manutenção PMOC · ' + mesTxt_(ref), subtitulo: ct['Cliente'] + ' · contrato ' + ct._id,
    corpo: identPmoc_(ct, c, eqs) +
      '<h2>3. Resumo de ' + h_(mesTxt_(ref)) + '</h2><table><tr><th>Equipamento</th><th>Localização</th><th>Itens</th><th>Situação</th></tr>' +
      ids.map(id => { const ls = porEq[id], e = eqs.find(x => x._id === id) || {}, k = ls.filter(r => r['Resultado'] === 'NOK').length;
        return '<tr><td>' + h_((e['Tipo'] || '') + ' · ' + id) + '</td><td>' + h_(e['Local / setor'] || '') + '</td><td>' + ls.length + '</td><td style="color:' + (k ? '#c0392b' : '#1d7a4b') + ';font-weight:bold">' + (k ? k + ' com problema' : 'Em ordem') + '</td></tr>'; }).join('') +
      faltam.map(e => '<tr><td>' + h_((e['Tipo'] || '') + ' · ' + e._id) + '</td><td>' + h_(e['Local / setor'] || '') + '</td><td>—</td><td style="color:#8a9aa1">Sem registro no mês</td></tr>').join('') + '</table>' +
      (nok.length ? '<div class="aviso">Itens com problema: ' + nok.map(r => h_(r['ID equipamento'] + ' · ' + r['Item'] + (r['Observação'] ? ' (' + r['Observação'] + ')' : ''))).join('; ') + '</div>' : '') +
      '<div class="desc">O laudo de cada equipamento, com os serviços feitos e as assinaturas, está nas folhas a seguir.</div>' };
  const pasta = pastaDe_({ reg: ct, raiz: 'docs', sub: 'Contratos', desc: ct['Cliente'] + ' · ' + ct['Tipo'] }, true);
  const r = salvarPdf_(pasta, 'Relatório PMOC ' + ct._id + ' ' + ref + '.pdf', docPaginas_([capa].concat(folhas)));
  log_('PMOC_RELATORIO', u.login, ct._id + ' · ' + ref);
  return { url: r.url, tel: String(c.tel || ''), cliente: ct['Cliente'], mesTxt: mesTxt_(ref), nok: nok.length, equipamentos: ids.length, trat: saudacao_(ct['Cliente']) };
}

/* ===== Qr.gs ===== */
/** Gerador de QR Code (biblioteca qrcode-generator de Kazuhiko Arase, licença MIT). Usado no PIX. Não precisa mexer. */
//---------------------------------------------------------------------
//
// QR Code Generator for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//  http://www.opensource.org/licenses/mit-license.php
//
// The word 'QR Code' is registered trademark of
// DENSO WAVE INCORPORATED
//  http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------

var qrcode = function() {

  //---------------------------------------------------------------------
  // qrcode
  //---------------------------------------------------------------------

  /**
   * qrcode
   * @param typeNumber 1 to 40
   * @param errorCorrectionLevel 'L','M','Q','H'
   */
  var qrcode = function(typeNumber, errorCorrectionLevel) {

    var PAD0 = 0xEC;
    var PAD1 = 0x11;

    var _typeNumber = typeNumber;
    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    var _modules = null;
    var _moduleCount = 0;
    var _dataCache = null;
    var _dataList = [];

    var _this = {};

    var makeImpl = function(test, maskPattern) {

      _moduleCount = _typeNumber * 4 + 17;
      _modules = function(moduleCount) {
        var modules = new Array(moduleCount);
        for (var row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (var col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      }(_moduleCount);

      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);

      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }

      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }

      mapData(_dataCache, maskPattern);
    };

    var setupPositionProbePattern = function(row, col) {

      for (var r = -1; r <= 7; r += 1) {

        if (row + r <= -1 || _moduleCount <= row + r) continue;

        for (var c = -1; c <= 7; c += 1) {

          if (col + c <= -1 || _moduleCount <= col + c) continue;

          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )
              || (0 <= c && c <= 6 && (r == 0 || r == 6) )
              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };

    var getBestMaskPattern = function() {

      var minLostPoint = 0;
      var pattern = 0;

      for (var i = 0; i < 8; i += 1) {

        makeImpl(true, i);

        var lostPoint = QRUtil.getLostPoint(_this);

        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }

      return pattern;
    };

    var setupTimingPattern = function() {

      for (var r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = (r % 2 == 0);
      }

      for (var c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = (c % 2 == 0);
      }
    };

    var setupPositionAdjustPattern = function() {

      var pos = QRUtil.getPatternPosition(_typeNumber);

      for (var i = 0; i < pos.length; i += 1) {

        for (var j = 0; j < pos.length; j += 1) {

          var row = pos[i];
          var col = pos[j];

          if (_modules[row][col] != null) {
            continue;
          }

          for (var r = -2; r <= 2; r += 1) {

            for (var c = -2; c <= 2; c += 1) {

              if (r == -2 || r == 2 || c == -2 || c == 2
                  || (r == 0 && c == 0) ) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };

    var setupTypeNumber = function(test) {

      var bits = QRUtil.getBCHTypeNumber(_typeNumber);

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };

    var setupTypeInfo = function(test, maskPattern) {

      var data = (_errorCorrectionLevel << 3) | maskPattern;
      var bits = QRUtil.getBCHTypeInfo(data);

      // vertical
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }

      // horizontal
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }

      // fixed module
      _modules[_moduleCount - 8][8] = (!test);
    };

    var mapData = function(data, maskPattern) {

      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      var maskFunc = QRUtil.getMaskFunction(maskPattern);

      for (var col = _moduleCount - 1; col > 0; col -= 2) {

        if (col == 6) col -= 1;

        while (true) {

          for (var c = 0; c < 2; c += 1) {

            if (_modules[row][col - c] == null) {

              var dark = false;

              if (byteIndex < data.length) {
                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);
              }

              var mask = maskFunc(row, col - c);

              if (mask) {
                dark = !dark;
              }

              _modules[row][col - c] = dark;
              bitIndex -= 1;

              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }

          row += inc;

          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };

    var createBytes = function(buffer, rsBlocks) {

      var offset = 0;

      var maxDcCount = 0;
      var maxEcCount = 0;

      var dcdata = new Array(rsBlocks.length);
      var ecdata = new Array(rsBlocks.length);

      for (var r = 0; r < rsBlocks.length; r += 1) {

        var dcCount = rsBlocks[r].dataCount;
        var ecCount = rsBlocks[r].totalCount - dcCount;

        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);

        dcdata[r] = new Array(dcCount);

        for (var i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;

        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);

        var modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (var i = 0; i < ecdata[r].length; i += 1) {
          var modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;
        }
      }

      var totalCodeCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }

      var data = new Array(totalCodeCount);
      var index = 0;

      for (var i = 0; i < maxDcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }

      for (var i = 0; i < maxEcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }

      return data;
    };

    var createData = function(typeNumber, errorCorrectionLevel, dataList) {

      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);

      var buffer = qrBitBuffer();

      for (var i = 0; i < dataList.length; i += 1) {
        var data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
        data.write(buffer);
      }

      // calc num max data.
      var totalDataCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }

      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw 'code length overflow. ('
          + buffer.getLengthInBits()
          + '>'
          + totalDataCount * 8
          + ')';
      }

      // end code
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }

      // padding
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }

      // padding
      while (true) {

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }

      return createBytes(buffer, rsBlocks);
    };

    _this.addData = function(data, mode) {

      mode = mode || 'Byte';

      var newData = null;

      switch(mode) {
      case 'Numeric' :
        newData = qrNumber(data);
        break;
      case 'Alphanumeric' :
        newData = qrAlphaNum(data);
        break;
      case 'Byte' :
        newData = qr8BitByte(data);
        break;
      case 'Kanji' :
        newData = qrKanji(data);
        break;
      default :
        throw 'mode:' + mode;
      }

      _dataList.push(newData);
      _dataCache = null;
    };

    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + ',' + col;
      }
      return _modules[row][col];
    };

    _this.getModuleCount = function() {
      return _moduleCount;
    };

    _this.make = function() {
      if (_typeNumber < 1) {
        var typeNumber = 1;

        for (; typeNumber < 40; typeNumber++) {
          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);
          var buffer = qrBitBuffer();

          for (var i = 0; i < _dataList.length; i++) {
            var data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
            data.write(buffer);
          }

          var totalDataCount = 0;
          for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }

          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }

        _typeNumber = typeNumber;
      }

      makeImpl(false, getBestMaskPattern() );
    };

    _this.createTableTag = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var qrHtml = '';

      qrHtml += '<table style="';
      qrHtml += ' border-width: 0px; border-style: none;';
      qrHtml += ' border-collapse: collapse;';
      qrHtml += ' padding: 0px; margin: ' + margin + 'px;';
      qrHtml += '">';
      qrHtml += '<tbody>';

      for (var r = 0; r < _this.getModuleCount(); r += 1) {

        qrHtml += '<tr>';

        for (var c = 0; c < _this.getModuleCount(); c += 1) {
          qrHtml += '<td style="';
          qrHtml += ' border-width: 0px; border-style: none;';
          qrHtml += ' border-collapse: collapse;';
          qrHtml += ' padding: 0px; margin: 0px;';
          qrHtml += ' width: ' + cellSize + 'px;';
          qrHtml += ' height: ' + cellSize + 'px;';
          qrHtml += ' background-color: ';
          qrHtml += _this.isDark(r, c)? '#000000' : '#ffffff';
          qrHtml += ';';
          qrHtml += '"/>';
        }

        qrHtml += '</tr>';
      }

      qrHtml += '</tbody>';
      qrHtml += '</table>';

      return qrHtml;
    };

    _this.createSvgTag = function(cellSize, margin, alt, title) {

      var opts = {};
      if (typeof arguments[0] == 'object') {
        // Called by options.
        opts = arguments[0];
        // overwrite cellSize and margin.
        cellSize = opts.cellSize;
        margin = opts.margin;
        alt = opts.alt;
        title = opts.title;
      }

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      // Compose alt property surrogate
      alt = (typeof alt === 'string') ? {text: alt} : alt || {};
      alt.text = alt.text || null;
      alt.id = (alt.text) ? alt.id || 'qrcode-description' : null;

      // Compose title property surrogate
      title = (typeof title === 'string') ? {text: title} : title || {};
      title.text = title.text || null;
      title.id = (title.text) ? title.id || 'qrcode-title' : null;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var c, mc, r, mr, qrSvg='', rect;

      rect = 'l' + cellSize + ',0 0,' + cellSize +
        ' -' + cellSize + ',0 0,-' + cellSize + 'z ';

      qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
      qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : '';
      qrSvg += ' viewBox="0 0 ' + size + ' ' + size + '" ';
      qrSvg += ' preserveAspectRatio="xMinYMin meet"';
      qrSvg += (title.text || alt.text) ? ' role="img" aria-labelledby="' +
          escapeXml([title.id, alt.id].join(' ').trim() ) + '"' : '';
      qrSvg += '>';
      qrSvg += (title.text) ? '<title id="' + escapeXml(title.id) + '">' +
          escapeXml(title.text) + '</title>' : '';
      qrSvg += (alt.text) ? '<description id="' + escapeXml(alt.id) + '">' +
          escapeXml(alt.text) + '</description>' : '';
      qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
      qrSvg += '<path d="';

      for (r = 0; r < _this.getModuleCount(); r += 1) {
        mr = r * cellSize + margin;
        for (c = 0; c < _this.getModuleCount(); c += 1) {
          if (_this.isDark(r, c) ) {
            mc = c*cellSize+margin;
            qrSvg += 'M' + mc + ',' + mr + rect;
          }
        }
      }

      qrSvg += '" stroke="transparent" fill="black"/>';
      qrSvg += '</svg>';

      return qrSvg;
    };

    _this.createDataURL = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      return createDataURL(size, size, function(x, y) {
        if (min <= x && x < max && min <= y && y < max) {
          var c = Math.floor( (x - min) / cellSize);
          var r = Math.floor( (y - min) / cellSize);
          return _this.isDark(r, c)? 0 : 1;
        } else {
          return 1;
        }
      } );
    };

    _this.createImgTag = function(cellSize, margin, alt) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;

      var img = '';
      img += '<img';
      img += '\u0020src="';
      img += _this.createDataURL(cellSize, margin);
      img += '"';
      img += '\u0020width="';
      img += size;
      img += '"';
      img += '\u0020height="';
      img += size;
      img += '"';
      if (alt) {
        img += '\u0020alt="';
        img += escapeXml(alt);
        img += '"';
      }
      img += '/>';

      return img;
    };

    var escapeXml = function(s) {
      var escaped = '';
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charAt(i);
        switch(c) {
        case '<': escaped += '&lt;'; break;
        case '>': escaped += '&gt;'; break;
        case '&': escaped += '&amp;'; break;
        case '"': escaped += '&quot;'; break;
        default : escaped += c; break;
        }
      }
      return escaped;
    };

    var _createHalfASCII = function(margin) {
      var cellSize = 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r1, r2, p;

      var blocks = {
        '██': '█',
        '█ ': '▀',
        ' █': '▄',
        '  ': ' '
      };

      var blocksLastLineNoMargin = {
        '██': '▀',
        '█ ': '▀',
        ' █': ' ',
        '  ': ' '
      };

      var ascii = '';
      for (y = 0; y < size; y += 2) {
        r1 = Math.floor((y - min) / cellSize);
        r2 = Math.floor((y + 1 - min) / cellSize);
        for (x = 0; x < size; x += 1) {
          p = '█';

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
            p = ' ';
          }

          if (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
            p += ' ';
          }
          else {
            p += '█';
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          ascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];
        }

        ascii += '\n';
      }

      if (size % 2 && margin > 0) {
        return ascii.substring(0, ascii.length - size - 1) + Array(size+1).join('▀');
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.createASCII = function(cellSize, margin) {
      cellSize = cellSize || 1;

      if (cellSize < 2) {
        return _createHalfASCII(margin);
      }

      cellSize -= 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r, p;

      var white = Array(cellSize+1).join('██');
      var black = Array(cellSize+1).join('  ');

      var ascii = '';
      var line = '';
      for (y = 0; y < size; y += 1) {
        r = Math.floor( (y - min) / cellSize);
        line = '';
        for (x = 0; x < size; x += 1) {
          p = 1;

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
            p = 0;
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          line += p ? white : black;
        }

        for (r = 0; r < cellSize; r += 1) {
          ascii += line + '\n';
        }
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.renderTo2dContext = function(context, cellSize) {
      cellSize = cellSize || 2;
      var length = _this.getModuleCount();
      for (var row = 0; row < length; row++) {
        for (var col = 0; col < length; col++) {
          context.fillStyle = _this.isDark(row, col) ? 'black' : 'white';
          context.fillRect(row * cellSize, col * cellSize, cellSize, cellSize);
        }
      }
    }

    return _this;
  };

  //---------------------------------------------------------------------
  // qrcode.stringToBytes
  //---------------------------------------------------------------------

  qrcode.stringToBytesFuncs = {
    'default' : function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        bytes.push(c & 0xff);
      }
      return bytes;
    }
  };

  qrcode.stringToBytes = qrcode.stringToBytesFuncs['default'];

  //---------------------------------------------------------------------
  // qrcode.createStringToBytes
  //---------------------------------------------------------------------

  /**
   * @param unicodeData base64 string of byte array.
   * [16bit Unicode],[16bit Bytes], ...
   * @param numChars
   */
  qrcode.createStringToBytes = function(unicodeData, numChars) {

    // create conversion map.

    var unicodeMap = function() {

      var bin = base64DecodeInputStream(unicodeData);
      var read = function() {
        var b = bin.read();
        if (b == -1) throw 'eof';
        return b;
      };

      var count = 0;
      var unicodeMap = {};
      while (true) {
        var b0 = bin.read();
        if (b0 == -1) break;
        var b1 = read();
        var b2 = read();
        var b3 = read();
        var k = String.fromCharCode( (b0 << 8) | b1);
        var v = (b2 << 8) | b3;
        unicodeMap[k] = v;
        count += 1;
      }
      if (count != numChars) {
        throw count + ' != ' + numChars;
      }

      return unicodeMap;
    }();

    var unknownChar = '?'.charCodeAt(0);

    return function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        if (c < 128) {
          bytes.push(c);
        } else {
          var b = unicodeMap[s.charAt(i)];
          if (typeof b == 'number') {
            if ( (b & 0xff) == b) {
              // 1byte
              bytes.push(b);
            } else {
              // 2bytes
              bytes.push(b >>> 8);
              bytes.push(b & 0xff);
            }
          } else {
            bytes.push(unknownChar);
          }
        }
      }
      return bytes;
    };
  };

  //---------------------------------------------------------------------
  // QRMode
  //---------------------------------------------------------------------

  var QRMode = {
    MODE_NUMBER :    1 << 0,
    MODE_ALPHA_NUM : 1 << 1,
    MODE_8BIT_BYTE : 1 << 2,
    MODE_KANJI :     1 << 3
  };

  //---------------------------------------------------------------------
  // QRErrorCorrectionLevel
  //---------------------------------------------------------------------

  var QRErrorCorrectionLevel = {
    L : 1,
    M : 0,
    Q : 3,
    H : 2
  };

  //---------------------------------------------------------------------
  // QRMaskPattern
  //---------------------------------------------------------------------

  var QRMaskPattern = {
    PATTERN000 : 0,
    PATTERN001 : 1,
    PATTERN010 : 2,
    PATTERN011 : 3,
    PATTERN100 : 4,
    PATTERN101 : 5,
    PATTERN110 : 6,
    PATTERN111 : 7
  };

  //---------------------------------------------------------------------
  // QRUtil
  //---------------------------------------------------------------------

  var QRUtil = function() {

    var PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);

    var _this = {};

    var getBCHDigit = function(data) {
      var digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };

    _this.getBCHTypeInfo = function(data) {
      var d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );
      }
      return ( (data << 10) | d) ^ G15_MASK;
    };

    _this.getBCHTypeNumber = function(data) {
      var d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );
      }
      return (data << 12) | d;
    };

    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };

    _this.getMaskFunction = function(maskPattern) {

      switch (maskPattern) {

      case QRMaskPattern.PATTERN000 :
        return function(i, j) { return (i + j) % 2 == 0; };
      case QRMaskPattern.PATTERN001 :
        return function(i, j) { return i % 2 == 0; };
      case QRMaskPattern.PATTERN010 :
        return function(i, j) { return j % 3 == 0; };
      case QRMaskPattern.PATTERN011 :
        return function(i, j) { return (i + j) % 3 == 0; };
      case QRMaskPattern.PATTERN100 :
        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };
      case QRMaskPattern.PATTERN101 :
        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };
      case QRMaskPattern.PATTERN110 :
        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };
      case QRMaskPattern.PATTERN111 :
        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };

      default :
        throw 'bad maskPattern:' + maskPattern;
      }
    };

    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      var a = qrPolynomial([1], 0);
      for (var i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );
      }
      return a;
    };

    _this.getLengthInBits = function(mode, type) {

      if (1 <= type && type < 10) {

        // 1 - 9

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 10;
        case QRMode.MODE_ALPHA_NUM : return 9;
        case QRMode.MODE_8BIT_BYTE : return 8;
        case QRMode.MODE_KANJI     : return 8;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 27) {

        // 10 - 26

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 12;
        case QRMode.MODE_ALPHA_NUM : return 11;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 10;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 41) {

        // 27 - 40

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 14;
        case QRMode.MODE_ALPHA_NUM : return 13;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 12;
        default :
          throw 'mode:' + mode;
        }

      } else {
        throw 'type:' + type;
      }
    };

    _this.getLostPoint = function(qrcode) {

      var moduleCount = qrcode.getModuleCount();

      var lostPoint = 0;

      // LEVEL1

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount; col += 1) {

          var sameCount = 0;
          var dark = qrcode.isDark(row, col);

          for (var r = -1; r <= 1; r += 1) {

            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }

            for (var c = -1; c <= 1; c += 1) {

              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }

              if (r == 0 && c == 0) {
                continue;
              }

              if (dark == qrcode.isDark(row + r, col + c) ) {
                sameCount += 1;
              }
            }
          }

          if (sameCount > 5) {
            lostPoint += (3 + sameCount - 5);
          }
        }
      };

      // LEVEL2

      for (var row = 0; row < moduleCount - 1; row += 1) {
        for (var col = 0; col < moduleCount - 1; col += 1) {
          var count = 0;
          if (qrcode.isDark(row, col) ) count += 1;
          if (qrcode.isDark(row + 1, col) ) count += 1;
          if (qrcode.isDark(row, col + 1) ) count += 1;
          if (qrcode.isDark(row + 1, col + 1) ) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }

      // LEVEL3

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row, col + 1)
              &&  qrcode.isDark(row, col + 2)
              &&  qrcode.isDark(row, col + 3)
              &&  qrcode.isDark(row, col + 4)
              && !qrcode.isDark(row, col + 5)
              &&  qrcode.isDark(row, col + 6) ) {
            lostPoint += 40;
          }
        }
      }

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row + 1, col)
              &&  qrcode.isDark(row + 2, col)
              &&  qrcode.isDark(row + 3, col)
              &&  qrcode.isDark(row + 4, col)
              && !qrcode.isDark(row + 5, col)
              &&  qrcode.isDark(row + 6, col) ) {
            lostPoint += 40;
          }
        }
      }

      // LEVEL4

      var darkCount = 0;

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount; row += 1) {
          if (qrcode.isDark(row, col) ) {
            darkCount += 1;
          }
        }
      }

      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;

      return lostPoint;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // QRMath
  //---------------------------------------------------------------------

  var QRMath = function() {

    var EXP_TABLE = new Array(256);
    var LOG_TABLE = new Array(256);

    // initialize tables
    for (var i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4]
        ^ EXP_TABLE[i - 5]
        ^ EXP_TABLE[i - 6]
        ^ EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i] ] = i;
    }

    var _this = {};

    _this.glog = function(n) {

      if (n < 1) {
        throw 'glog(' + n + ')';
      }

      return LOG_TABLE[n];
    };

    _this.gexp = function(n) {

      while (n < 0) {
        n += 255;
      }

      while (n >= 256) {
        n -= 255;
      }

      return EXP_TABLE[n];
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrPolynomial
  //---------------------------------------------------------------------

  function qrPolynomial(num, shift) {

    if (typeof num.length == 'undefined') {
      throw num.length + '/' + shift;
    }

    var _num = function() {
      var offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      var _num = new Array(num.length - offset + shift);
      for (var i = 0; i < num.length - offset; i += 1) {
        _num[i] = num[i + offset];
      }
      return _num;
    }();

    var _this = {};

    _this.getAt = function(index) {
      return _num[index];
    };

    _this.getLength = function() {
      return _num.length;
    };

    _this.multiply = function(e) {

      var num = new Array(_this.getLength() + e.getLength() - 1);

      for (var i = 0; i < _this.getLength(); i += 1) {
        for (var j = 0; j < e.getLength(); j += 1) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );
        }
      }

      return qrPolynomial(num, 0);
    };

    _this.mod = function(e) {

      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }

      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );

      var num = new Array(_this.getLength() );
      for (var i = 0; i < _this.getLength(); i += 1) {
        num[i] = _this.getAt(i);
      }

      for (var i = 0; i < e.getLength(); i += 1) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);
      }

      // recursive call
      return qrPolynomial(num, 0).mod(e);
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // QRRSBlock
  //---------------------------------------------------------------------

  var QRRSBlock = function() {

    var RS_BLOCK_TABLE = [

      // L
      // M
      // Q
      // H

      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],

      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],

      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],

      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],

      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],

      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],

      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],

      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],

      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],

      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],

      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],

      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],

      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],

      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],

      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],

      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],

      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],

      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],

      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],

      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],

      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],

      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],

      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],

      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],

      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],

      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],

      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],

      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],

      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],

      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],

      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],

      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],

      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],

      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],

      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],

      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],

      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],

      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],

      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],

      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];

    var qrRSBlock = function(totalCount, dataCount) {
      var _this = {};
      _this.totalCount = totalCount;
      _this.dataCount = dataCount;
      return _this;
    };

    var _this = {};

    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {

      switch(errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default :
        return undefined;
      }
    };

    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {

      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);

      if (typeof rsBlock == 'undefined') {
        throw 'bad rs block @ typeNumber:' + typeNumber +
            '/errorCorrectionLevel:' + errorCorrectionLevel;
      }

      var length = rsBlock.length / 3;

      var list = [];

      for (var i = 0; i < length; i += 1) {

        var count = rsBlock[i * 3 + 0];
        var totalCount = rsBlock[i * 3 + 1];
        var dataCount = rsBlock[i * 3 + 2];

        for (var j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount) );
        }
      }

      return list;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrBitBuffer
  //---------------------------------------------------------------------

  var qrBitBuffer = function() {

    var _buffer = [];
    var _length = 0;

    var _this = {};

    _this.getBuffer = function() {
      return _buffer;
    };

    _this.getAt = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;
    };

    _this.put = function(num, length) {
      for (var i = 0; i < length; i += 1) {
        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);
      }
    };

    _this.getLengthInBits = function() {
      return _length;
    };

    _this.putBit = function(bit) {

      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }

      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );
      }

      _length += 1;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrNumber
  //---------------------------------------------------------------------

  var qrNumber = function(data) {

    var _mode = QRMode.MODE_NUMBER;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var data = _data;

      var i = 0;

      while (i + 2 < data.length) {
        buffer.put(strToNum(data.substring(i, i + 3) ), 10);
        i += 3;
      }

      if (i < data.length) {
        if (data.length - i == 1) {
          buffer.put(strToNum(data.substring(i, i + 1) ), 4);
        } else if (data.length - i == 2) {
          buffer.put(strToNum(data.substring(i, i + 2) ), 7);
        }
      }
    };

    var strToNum = function(s) {
      var num = 0;
      for (var i = 0; i < s.length; i += 1) {
        num = num * 10 + chatToNum(s.charAt(i) );
      }
      return num;
    };

    var chatToNum = function(c) {
      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      }
      throw 'illegal char :' + c;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrAlphaNum
  //---------------------------------------------------------------------

  var qrAlphaNum = function(data) {

    var _mode = QRMode.MODE_ALPHA_NUM;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var s = _data;

      var i = 0;

      while (i + 1 < s.length) {
        buffer.put(
          getCode(s.charAt(i) ) * 45 +
          getCode(s.charAt(i + 1) ), 11);
        i += 2;
      }

      if (i < s.length) {
        buffer.put(getCode(s.charAt(i) ), 6);
      }
    };

    var getCode = function(c) {

      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      } else if ('A' <= c && c <= 'Z') {
        return c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
      } else {
        switch (c) {
        case ' ' : return 36;
        case '$' : return 37;
        case '%' : return 38;
        case '*' : return 39;
        case '+' : return 40;
        case '-' : return 41;
        case '.' : return 42;
        case '/' : return 43;
        case ':' : return 44;
        default :
          throw 'illegal char :' + c;
        }
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qr8BitByte
  //---------------------------------------------------------------------

  var qr8BitByte = function(data) {

    var _mode = QRMode.MODE_8BIT_BYTE;
    var _data = data;
    var _bytes = qrcode.stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _bytes.length;
    };

    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrKanji
  //---------------------------------------------------------------------

  var qrKanji = function(data) {

    var _mode = QRMode.MODE_KANJI;
    var _data = data;

    var stringToBytes = qrcode.stringToBytesFuncs['SJIS'];
    if (!stringToBytes) {
      throw 'sjis not supported.';
    }
    !function(c, code) {
      // self test for sjis support.
      var test = stringToBytes(c);
      if (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {
        throw 'sjis not supported.';
      }
    }('\u53cb', 0x9746);

    var _bytes = stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return ~~(_bytes.length / 2);
    };

    _this.write = function(buffer) {

      var data = _bytes;

      var i = 0;

      while (i + 1 < data.length) {

        var c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);

        if (0x8140 <= c && c <= 0x9FFC) {
          c -= 0x8140;
        } else if (0xE040 <= c && c <= 0xEBBF) {
          c -= 0xC140;
        } else {
          throw 'illegal char at ' + (i + 1) + '/' + c;
        }

        c = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);

        buffer.put(c, 13);

        i += 2;
      }

      if (i < data.length) {
        throw 'illegal char at ' + (i + 1);
      }
    };

    return _this;
  };

  //=====================================================================
  // GIF Support etc.
  //

  //---------------------------------------------------------------------
  // byteArrayOutputStream
  //---------------------------------------------------------------------

  var byteArrayOutputStream = function() {

    var _bytes = [];

    var _this = {};

    _this.writeByte = function(b) {
      _bytes.push(b & 0xff);
    };

    _this.writeShort = function(i) {
      _this.writeByte(i);
      _this.writeByte(i >>> 8);
    };

    _this.writeBytes = function(b, off, len) {
      off = off || 0;
      len = len || b.length;
      for (var i = 0; i < len; i += 1) {
        _this.writeByte(b[i + off]);
      }
    };

    _this.writeString = function(s) {
      for (var i = 0; i < s.length; i += 1) {
        _this.writeByte(s.charCodeAt(i) );
      }
    };

    _this.toByteArray = function() {
      return _bytes;
    };

    _this.toString = function() {
      var s = '';
      s += '[';
      for (var i = 0; i < _bytes.length; i += 1) {
        if (i > 0) {
          s += ',';
        }
        s += _bytes[i];
      }
      s += ']';
      return s;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64EncodeOutputStream
  //---------------------------------------------------------------------

  var base64EncodeOutputStream = function() {

    var _buffer = 0;
    var _buflen = 0;
    var _length = 0;
    var _base64 = '';

    var _this = {};

    var writeEncoded = function(b) {
      _base64 += String.fromCharCode(encode(b & 0x3f) );
    };

    var encode = function(n) {
      if (n < 0) {
        // error.
      } else if (n < 26) {
        return 0x41 + n;
      } else if (n < 52) {
        return 0x61 + (n - 26);
      } else if (n < 62) {
        return 0x30 + (n - 52);
      } else if (n == 62) {
        return 0x2b;
      } else if (n == 63) {
        return 0x2f;
      }
      throw 'n:' + n;
    };

    _this.writeByte = function(n) {

      _buffer = (_buffer << 8) | (n & 0xff);
      _buflen += 8;
      _length += 1;

      while (_buflen >= 6) {
        writeEncoded(_buffer >>> (_buflen - 6) );
        _buflen -= 6;
      }
    };

    _this.flush = function() {

      if (_buflen > 0) {
        writeEncoded(_buffer << (6 - _buflen) );
        _buffer = 0;
        _buflen = 0;
      }

      if (_length % 3 != 0) {
        // padding
        var padlen = 3 - _length % 3;
        for (var i = 0; i < padlen; i += 1) {
          _base64 += '=';
        }
      }
    };

    _this.toString = function() {
      return _base64;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64DecodeInputStream
  //---------------------------------------------------------------------

  var base64DecodeInputStream = function(str) {

    var _str = str;
    var _pos = 0;
    var _buffer = 0;
    var _buflen = 0;

    var _this = {};

    _this.read = function() {

      while (_buflen < 8) {

        if (_pos >= _str.length) {
          if (_buflen == 0) {
            return -1;
          }
          throw 'unexpected end of file./' + _buflen;
        }

        var c = _str.charAt(_pos);
        _pos += 1;

        if (c == '=') {
          _buflen = 0;
          return -1;
        } else if (c.match(/^\s$/) ) {
          // ignore if whitespace.
          continue;
        }

        _buffer = (_buffer << 6) | decode(c.charCodeAt(0) );
        _buflen += 6;
      }

      var n = (_buffer >>> (_buflen - 8) ) & 0xff;
      _buflen -= 8;
      return n;
    };

    var decode = function(c) {
      if (0x41 <= c && c <= 0x5a) {
        return c - 0x41;
      } else if (0x61 <= c && c <= 0x7a) {
        return c - 0x61 + 26;
      } else if (0x30 <= c && c <= 0x39) {
        return c - 0x30 + 52;
      } else if (c == 0x2b) {
        return 62;
      } else if (c == 0x2f) {
        return 63;
      } else {
        throw 'c:' + c;
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // gifImage (B/W)
  //---------------------------------------------------------------------

  var gifImage = function(width, height) {

    var _width = width;
    var _height = height;
    var _data = new Array(width * height);

    var _this = {};

    _this.setPixel = function(x, y, pixel) {
      _data[y * _width + x] = pixel;
    };

    _this.write = function(out) {

      //---------------------------------
      // GIF Signature

      out.writeString('GIF87a');

      //---------------------------------
      // Screen Descriptor

      out.writeShort(_width);
      out.writeShort(_height);

      out.writeByte(0x80); // 2bit
      out.writeByte(0);
      out.writeByte(0);

      //---------------------------------
      // Global Color Map

      // black
      out.writeByte(0x00);
      out.writeByte(0x00);
      out.writeByte(0x00);

      // white
      out.writeByte(0xff);
      out.writeByte(0xff);
      out.writeByte(0xff);

      //---------------------------------
      // Image Descriptor

      out.writeString(',');
      out.writeShort(0);
      out.writeShort(0);
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(0);

      //---------------------------------
      // Local Color Map

      //---------------------------------
      // Raster Data

      var lzwMinCodeSize = 2;
      var raster = getLZWRaster(lzwMinCodeSize);

      out.writeByte(lzwMinCodeSize);

      var offset = 0;

      while (raster.length - offset > 255) {
        out.writeByte(255);
        out.writeBytes(raster, offset, 255);
        offset += 255;
      }

      out.writeByte(raster.length - offset);
      out.writeBytes(raster, offset, raster.length - offset);
      out.writeByte(0x00);

      //---------------------------------
      // GIF Terminator
      out.writeString(';');
    };

    var bitOutputStream = function(out) {

      var _out = out;
      var _bitLength = 0;
      var _bitBuffer = 0;

      var _this = {};

      _this.write = function(data, length) {

        if ( (data >>> length) != 0) {
          throw 'length over';
        }

        while (_bitLength + length >= 8) {
          _out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );
          length -= (8 - _bitLength);
          data >>>= (8 - _bitLength);
          _bitBuffer = 0;
          _bitLength = 0;
        }

        _bitBuffer = (data << _bitLength) | _bitBuffer;
        _bitLength = _bitLength + length;
      };

      _this.flush = function() {
        if (_bitLength > 0) {
          _out.writeByte(_bitBuffer);
        }
      };

      return _this;
    };

    var getLZWRaster = function(lzwMinCodeSize) {

      var clearCode = 1 << lzwMinCodeSize;
      var endCode = (1 << lzwMinCodeSize) + 1;
      var bitLength = lzwMinCodeSize + 1;

      // Setup LZWTable
      var table = lzwTable();

      for (var i = 0; i < clearCode; i += 1) {
        table.add(String.fromCharCode(i) );
      }
      table.add(String.fromCharCode(clearCode) );
      table.add(String.fromCharCode(endCode) );

      var byteOut = byteArrayOutputStream();
      var bitOut = bitOutputStream(byteOut);

      // clear code
      bitOut.write(clearCode, bitLength);

      var dataIndex = 0;

      var s = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;

      while (dataIndex < _data.length) {

        var c = String.fromCharCode(_data[dataIndex]);
        dataIndex += 1;

        if (table.contains(s + c) ) {

          s = s + c;

        } else {

          bitOut.write(table.indexOf(s), bitLength);

          if (table.size() < 0xfff) {

            if (table.size() == (1 << bitLength) ) {
              bitLength += 1;
            }

            table.add(s + c);
          }

          s = c;
        }
      }

      bitOut.write(table.indexOf(s), bitLength);

      // end code
      bitOut.write(endCode, bitLength);

      bitOut.flush();

      return byteOut.toByteArray();
    };

    var lzwTable = function() {

      var _map = {};
      var _size = 0;

      var _this = {};

      _this.add = function(key) {
        if (_this.contains(key) ) {
          throw 'dup key:' + key;
        }
        _map[key] = _size;
        _size += 1;
      };

      _this.size = function() {
        return _size;
      };

      _this.indexOf = function(key) {
        return _map[key];
      };

      _this.contains = function(key) {
        return typeof _map[key] != 'undefined';
      };

      return _this;
    };

    return _this;
  };

  var createDataURL = function(width, height, getPixel) {
    var gif = gifImage(width, height);
    for (var y = 0; y < height; y += 1) {
      for (var x = 0; x < width; x += 1) {
        gif.setPixel(x, y, getPixel(x, y) );
      }
    }

    var b = byteArrayOutputStream();
    gif.write(b);

    var base64 = base64EncodeOutputStream();
    var bytes = b.toByteArray();
    for (var i = 0; i < bytes.length; i += 1) {
      base64.writeByte(bytes[i]);
    }
    base64.flush();

    return 'data:image/gif;base64,' + base64;
  };

  //---------------------------------------------------------------------
  // returns qrcode function.

  return qrcode;
}();

/* ===== Tabelas.gs ===== */
/** ===================== TABELAS (ligação com as planilhas) =====================
 * Cada tabela aponta para uma aba. As colunas são achadas PELO NOME do cabeçalho,
 * então mudar a ordem das colunas na planilha não quebra o sistema.
 *
 * Tipos de campo: texto, area, data, hora, dinheiro, numero, lista, simnao, bool, info (só leitura), link
 * opcoes: lista fixa  |  'LISTAS:<cabeçalho>' (aba LISTAS da Operação)  |  'TAB:<TABELA>:<coluna>'  |  'TECNICOS'
 * id: coluna do código fixo (já vem preenchido nas linhas da planilha)
 * chave: coluna que indica que a linha está em uso (linha com chave vazia = livre para cadastro novo)
 * filtros: campos que viram filtro na tela  ·  mes: campo de data usado para navegar por mês
 */
const TABELAS = {
  SERVICOS: {
    planilha: 'OPERACAO', aba: 'SERVIÇOS', id: 'Nº OS', chave: 'Cliente', titulo: 'Serviço', novo: 'Novo serviço',
    card: { titulo: 'Cliente', sub: ['Tipo', 'Técnico', 'Contrato'], data: 'Agendado para', selo: 'Situação', alerta: 'Alerta', valor: 'Valor', anexo: ['Pasta / fotos', 'Comprovante'] },
    ordem: { campo: 'Agendado para', desc: false },
    filtros: ['Situação', 'Técnico', 'Tipo', 'Alerta'], mes: 'Agendado para',
    campos: [
      { c: 'Cliente', t: 'lista', opcoes: 'TAB:CLIENTES:Nome / razão social', obrig: true },
      { c: 'Tipo', t: 'lista', opcoes: 'LISTAS:Tipos de serviço' },
      { c: 'Descrição', t: 'area' },
      { c: 'Técnico', t: 'lista', opcoes: 'TECNICOS' },
      { c: 'Aberto em', t: 'data', padrao: 'hoje' },
      { c: 'Agendado para', t: 'data' },
      { c: 'Situação', t: 'lista', opcoes: 'LISTAS:Situação do serviço', padrao: 'Orçamento' },
      { c: 'Concluído em', t: 'data' },
      { c: 'Valor', t: 'dinheiro' },
      { c: 'Pago?', t: 'simnao' },
      { c: 'Contrato', t: 'lista', opcoes: 'CONTRATOS', rotulo: 'Contrato (se o serviço for coberto por contrato, pode deixar sem valor)' },
      { c: 'Alerta', t: 'info' },
      { c: 'Materiais (R$)', t: 'info', tipoInfo: 'dinheiro' },
      { c: 'Pasta / fotos', t: 'link', sistema: true },
      { c: 'Comprovante', t: 'link', sistema: true }
    ]
  },
  CLIENTES: {
    planilha: 'OPERACAO', aba: 'CLIENTES', id: 'ID', chave: 'Nome / razão social', titulo: 'Cliente', novo: 'Novo cliente',
    card: { titulo: 'Nome / razão social', sub: ['Telefone', 'Bairro', 'Cidade'], selo: 'Tipo' },
    ordem: { campo: 'Nome / razão social' },
    filtros: ['Tipo', 'Pessoa', 'Cidade', 'Bairro', '_contrato'],
    campos: [
      { c: 'Nome / razão social', t: 'texto', obrig: true },
      { c: 'CPF / CNPJ', t: 'texto' }, { c: 'Telefone', t: 'texto', tel: true }, { c: 'E-mail', t: 'texto' },
      { c: 'Endereço', t: 'texto' }, { c: 'Bairro', t: 'texto' }, { c: 'Cidade', t: 'texto', padrao: 'Uberlândia' },
      { c: 'Tipo', t: 'lista', opcoes: 'LISTAS:Tipo de cliente' },
      { c: 'Pessoa', t: 'lista', opcoes: 'LISTAS:Pessoa', rotulo: 'Pessoa física ou jurídica' },
      { c: 'Gênero', t: 'lista', opcoes: 'LISTAS:Gênero', rotulo: 'Gênero (para os documentos: Sr., Sra. ou neutro)' },
      { c: 'Contato no local', t: 'texto' }, { c: 'Observações', t: 'area' }
    ]
  },
  CONTRATOS: {
    planilha: 'OPERACAO', aba: 'CONTRATOS', id: 'ID', chave: 'Cliente', titulo: 'Contrato', novo: 'Novo contrato',
    card: { titulo: 'Cliente', sub: ['Tipo', 'Serviços incluídos'], data: 'Fim', selo: 'Situação', alerta: 'Alerta', valor: 'Valor', anexo: ['Arquivos'] },
    ordem: { campo: 'Cliente' },
    filtros: ['Tipo', 'Situação', 'Alerta'],
    campos: [
      { c: 'Cliente', t: 'lista', opcoes: 'TAB:CLIENTES:Nome / razão social', obrig: true },
      { c: 'Tipo', t: 'lista', opcoes: 'LISTAS:Tipos de contrato', padrao: 'Mensal', obrig: true },
      { c: 'Serviços incluídos', t: 'area' },
      { c: 'Valor', t: 'dinheiro', rotulo: 'Valor (por mês, se for mensal)' },
      { c: 'Início', t: 'data', padrao: 'hoje' }, { c: 'Fim', t: 'data', rotulo: 'Fim (em branco = sem prazo)' },
      { c: 'Dia de vencimento', t: 'numero' },
      { c: 'Situação', t: 'lista', opcoes: ['Ativo', 'Suspenso', 'Encerrado'], padrao: 'Ativo' },
      { c: 'Alerta', t: 'info' },
      { c: 'Orçamento', t: 'lista', opcoes: 'ORCAMENTOS', rotulo: 'Orçamento (os itens vão para o contrato)' },
      { c: 'Forma de pagamento', t: 'lista', opcoes: ['PIX', 'Boleto', 'Cartão', 'Dinheiro', 'Transferência'] },
      { c: 'ART / TRT', t: 'texto', rotulo: 'Nº da ART / TRT (contratos PMOC)' },
      { c: 'Observações', t: 'area' }, { c: 'Arquivos', t: 'link', sistema: true }, { c: 'Documento', t: 'link', sistema: true },
      { c: 'Plano PMOC', t: 'link', sistema: true }
    ]
  },
  ORCAMENTOS: {
    planilha: 'OPERACAO', aba: 'ORÇAMENTOS', id: 'Nº orçamento', chave: 'Cliente', titulo: 'Orçamento', novo: 'Novo orçamento',
    card: { titulo: 'Cliente', sub: ['Tipo', 'Feito por'], data: 'Data', selo: 'Situação', alerta: 'Alerta', valor: 'Total', anexo: ['PDF'] },
    ordem: { campo: 'Data', desc: true },
    filtros: ['Situação', 'Tipo', 'Alerta', 'Feito por'], mes: 'Data',
    campos: [
      { c: 'Cliente', t: 'lista', opcoes: 'TAB:CLIENTES:Nome / razão social', obrig: true },
      { c: 'Data', t: 'data', padrao: 'hoje' }, { c: 'Validade (dias)', t: 'numero' }, { c: 'Válido até', t: 'info', tipoInfo: 'data' },
      { c: 'Situação', t: 'lista', opcoes: ['Aberto', 'Enviado', 'Aprovado', 'Recusado'], padrao: 'Aberto' },
      { c: 'Alerta', t: 'info' }, { c: 'Subtotal', t: 'info', tipoInfo: 'dinheiro' }, { c: 'Desconto', t: 'dinheiro' }, { c: 'Total', t: 'info', tipoInfo: 'dinheiro' },
      { c: 'Tipo', t: 'lista', opcoes: ['Serviço avulso', 'Contrato mensal', 'Contrato PMOC', 'Contrato anual'], padrao: 'Serviço avulso' },
      { c: 'Observações', t: 'area' }, { c: 'Feito por', t: 'info', sistema: true }, { c: 'PDF', t: 'link', sistema: true }, { c: 'OS gerada', t: 'info', sistema: true },
      { c: 'Contrato gerado', t: 'info', sistema: true }, { c: 'Lançamento', t: 'info', sistema: true }
    ]
  },
  ITENS_ORC: {
    planilha: 'OPERACAO', aba: 'ITENS DO ORÇAMENTO', id: 'ID', chave: 'Serviço', titulo: 'Item', novo: 'Item',
    card: { titulo: 'Serviço' },
    campos: [
      { c: 'Nº orçamento', t: 'texto' }, { c: 'Serviço', t: 'texto' }, { c: 'Descrição', t: 'texto' },
      { c: 'Quantidade', t: 'numero' }, { c: 'Valor unitário', t: 'dinheiro' }, { c: 'Total', t: 'info', tipoInfo: 'dinheiro' }
    ]
  },
  PRECOS: {
    planilha: 'OPERACAO', aba: 'TABELA DE PREÇOS', id: 'ID', chave: 'Serviço', titulo: 'Preço', novo: 'Novo serviço na tabela',
    card: { titulo: 'Serviço', sub: ['Descrição', 'Unidade'], valor: 'Valor', selo: 'Ativo?' },
    ordem: { campo: 'Serviço' },
    filtros: ['Ativo?', 'Unidade'],
    campos: [
      { c: 'Serviço', t: 'texto', obrig: true }, { c: 'Descrição', t: 'texto' },
      { c: 'Unidade', t: 'lista', opcoes: ['aparelho', 'visita', 'm', 'kg', 'h', 'un', 'plano', 'mês'] },
      { c: 'Valor', t: 'dinheiro' }, { c: 'Ativo?', t: 'lista', opcoes: ['Sim', 'Não'], padrao: 'Sim' }
    ]
  },
  EQUIPAMENTOS: {
    planilha: 'OPERACAO', aba: 'EQUIPAMENTOS', id: 'ID', chave: 'Cliente', titulo: 'Equipamento', novo: 'Novo equipamento',
    card: { titulo: 'Cliente', sub: ['Local / setor', 'Tipo', 'Capacidade'], selo: 'Marca', anexo: ['Fotos'] },
    ordem: { campo: 'Cliente' },
    filtros: ['Cliente', 'Tipo', 'Marca'],
    campos: [
      { c: 'Cliente', t: 'lista', opcoes: 'TAB:CLIENTES:Nome / razão social', obrig: true },
      { c: 'Local / setor', t: 'texto' }, { c: 'Tipo', t: 'lista', opcoes: 'LISTAS:Tipos de equipamento' },
      { c: 'Marca', t: 'texto' }, { c: 'Capacidade', t: 'texto' }, { c: 'Modelo', t: 'texto' },
      { c: 'Nº de série', t: 'texto' },
      { c: 'Contrato', t: 'lista', opcoes: 'CONTRATOS', rotulo: 'Contrato (PMOC) que cobre este aparelho' },
      { c: 'Área (m²)', t: 'numero', rotulo: 'Área do ambiente (m²)' }, { c: 'Ocupantes', t: 'numero', rotulo: 'Ocupantes do ambiente' },
      { c: 'Observações', t: 'area' }, { c: 'Fotos', t: 'link', sistema: true }
    ]
  },
  CHECKLIST: {
    planilha: 'OPERACAO', aba: 'CHECKLIST PMOC', id: 'ID', chave: 'Item', crescer: true, titulo: 'Item do checklist', novo: 'Novo item do checklist',
    card: { titulo: 'Item', sub: ['Checklist', 'Grupo', 'Resposta'], selo: 'Periodicidade' },
    ordem: { campo: 'Ordem' },
    filtros: ['Checklist', 'Periodicidade', 'Grupo', 'Ativo?'],
    campos: [
      { c: 'Checklist', t: 'lista', opcoes: 'CHECKLISTS', obrig: true, rotulo: 'Checklist (modelo)' },
      { c: 'Grupo', t: 'texto', rotulo: 'Grupo (ex.: Evaporadora, Quadro elétrico, Medições)' },
      { c: 'Item', t: 'texto', obrig: true },
      { c: 'Periodicidade', t: 'lista', opcoes: ['Mensal', 'Bimestral', 'Trimestral', 'Semestral', 'Anual'], padrao: 'Mensal', obrig: true },
      { c: 'Resposta', t: 'lista', opcoes: ['OK/NOK/NA', 'Medição'], padrao: 'OK/NOK/NA', rotulo: 'Resposta (marcar OK/NOK ou anotar uma medida)' },
      { c: 'Unidade', t: 'texto', rotulo: 'Unidade da medida (°C, A, V, psi…)' },
      { c: 'Ativo?', t: 'lista', opcoes: ['Sim', 'Não'], padrao: 'Sim' },
      { c: 'Ordem', t: 'numero' }
    ]
  },
  TIPOS_EQ: {
    planilha: 'OPERACAO', aba: 'TIPOS DE EQUIPAMENTO', id: 'ID', chave: 'Tipo de equipamento', crescer: true, titulo: 'Tipo de equipamento', novo: 'Novo tipo de equipamento',
    card: { titulo: 'Tipo de equipamento', sub: ['Observação'], selo: 'Checklist PMOC' },
    ordem: { campo: 'Tipo de equipamento' },
    filtros: ['Checklist PMOC'],
    campos: [
      { c: 'Tipo de equipamento', t: 'texto', obrig: true },
      { c: 'Checklist PMOC', t: 'lista', opcoes: 'CHECKLISTS', rotulo: 'Checklist PMOC usado por este tipo' },
      { c: 'Observação', t: 'texto' }
    ]
  },
  BANCO: {
    planilha: 'OPERACAO', aba: 'BANCO DE ITENS', id: 'ID', chave: 'Item', crescer: true, titulo: 'Item do banco', novo: 'Novo item',
    card: { titulo: 'Item', sub: ['Grupo', 'Resposta'], selo: 'Periodicidade' },
    ordem: { campo: 'Grupo' },
    filtros: ['Grupo', 'Periodicidade'],
    campos: [
      { c: 'Grupo', t: 'texto', obrig: true }, { c: 'Item', t: 'texto', obrig: true },
      { c: 'Periodicidade', t: 'lista', opcoes: ['Mensal', 'Bimestral', 'Trimestral', 'Semestral', 'Anual'], padrao: 'Mensal' },
      { c: 'Resposta', t: 'lista', opcoes: ['OK/NOK/NA', 'Medição'], padrao: 'OK/NOK/NA' }, { c: 'Unidade', t: 'texto' }
    ]
  },
  CLAUSULAS: {
    planilha: 'SISTEMA', aba: 'CLÁUSULAS DO CONTRATO', id: 'ID', chave: 'Título', crescer: true, titulo: 'Cláusula', novo: 'Nova cláusula',
    card: { titulo: 'Título', sub: ['Vale para', 'Ordem'], selo: 'Ativo?' },
    ordem: { campo: 'Ordem' },
    filtros: ['Vale para', 'Ativo?'],
    campos: [
      { c: 'Ordem', t: 'numero' },
      { c: 'Título', t: 'texto', obrig: true },
      { c: 'Texto', t: 'area', obrig: true, rotulo: 'Texto (pode usar {VALOR}, {INICIO}, {ATE}, {FORO}, {GARANTIA}, {SERVICOS}…)' },
      { c: 'Vale para', t: 'lista', opcoes: ['Todos', 'Contínuo', 'Serviço único', 'PMOC'], padrao: 'Todos', rotulo: 'Vale para (Contínuo = mensal, PMOC, anual)' },
      { c: 'Ativo?', t: 'lista', opcoes: ['Sim', 'Não'], padrao: 'Sim' }
    ]
  },
  PMOC: {
    planilha: 'OPERACAO', aba: 'PMOC', id: 'ID', chave: 'Equipamento', titulo: 'PMOC', novo: 'Novo PMOC',
    card: { titulo: 'Equipamento', sub: ['Frequência', 'Responsável técnico'], data: 'Próxima', selo: 'Situação' },
    ordem: { campo: 'Próxima' },
    filtros: ['Situação', 'Frequência'],
    campos: [
      { c: 'Equipamento', t: 'lista', opcoes: 'TAB:EQUIPAMENTOS:Nome na lista', obrig: true },
      { c: 'Frequência', t: 'lista', opcoes: 'LISTAS:Frequência' },
      { c: 'Última manutenção', t: 'data' },
      { c: 'Próxima', t: 'info', tipoInfo: 'data' }, { c: 'Situação', t: 'info' },
      { c: 'Responsável técnico', t: 'texto' }, { c: 'Observações', t: 'area' }
    ]
  },
  ESTOQUE: {
    planilha: 'OPERACAO', aba: 'ESTOQUE', id: 'ID', chave: 'Item', titulo: 'Item', novo: 'Novo item',
    card: { titulo: 'Item', sub: ['Categoria', 'Quantidade', 'Unidade'], selo: 'Situação', valor: 'Valor unitário' },
    ordem: { campo: 'Item' },
    filtros: ['Categoria', 'Situação'],
    campos: [
      { c: 'Item', t: 'texto', obrig: true }, { c: 'Categoria', t: 'lista', opcoes: 'LISTAS:Categorias de estoque' },
      { c: 'Unidade', t: 'texto' }, { c: 'Quantidade', t: 'numero' }, { c: 'Mínimo', t: 'numero' }, { c: 'Situação', t: 'info' },
      { c: 'Fornecedor', t: 'texto' }, { c: 'Valor unitário', t: 'dinheiro' }, { c: 'Observações', t: 'area' }
    ]
  },
  MATERIAIS: {
    planilha: 'OPERACAO', aba: 'MATERIAIS', id: 'ID', chave: 'Item', titulo: 'Material usado', novo: 'Usar material',
    card: { titulo: 'Item', sub: ['Nº OS', 'Quantidade', 'Unidade'], valor: 'Total' },
    campos: [
      { c: 'Data', t: 'data' }, { c: 'Nº OS', t: 'texto' }, { c: 'Item', t: 'texto' }, { c: 'Quantidade', t: 'numero' },
      { c: 'Unidade', t: 'texto' }, { c: 'Valor unitário', t: 'dinheiro' }, { c: 'Total', t: 'info', tipoInfo: 'dinheiro' },
      { c: 'Lançado por', t: 'info', sistema: true }, { c: 'ID item', t: 'info', sistema: true }
    ]
  },
  MOVIMENTO: {
    planilha: 'FINANCEIRO', aba: 'MOVIMENTO', id: 'ID (sistema)', chave: 'Valor', titulo: 'Lançamento', novo: 'Novo lançamento',
    card: { titulo: 'Descrição', sub: ['Categoria', 'Confirmado por'], data: 'Data', selo: 'Entrada ou saída', valor: 'Valor', check: 'Pago?', anexo: ['Comprovante', 'Recibo'] },
    ordem: { campo: 'Data', desc: true },
    filtros: ['Entrada ou saída', 'Categoria', '_pago'], mes: 'Data',
    campos: [
      { c: 'Data', t: 'data', padrao: 'hoje', obrig: true },
      { c: 'Entrada ou saída', t: 'lista', opcoes: ['Entrada', 'Saída'], obrig: true },
      { c: 'Descrição', t: 'texto' },
      { c: 'Categoria', t: 'lista', opcoes: ['Serviço', 'Contrato', 'Venda de peças', 'Material e peças', 'Combustível', 'Ferramentas',
        'Salários e diárias', 'Aluguel e contas', 'Impostos e taxas', 'Retirada dos sócios', 'Saldo inicial', 'Outros'] },
      { c: 'Valor', t: 'dinheiro', obrig: true },
      { c: 'Pago?', t: 'bool', padrao: true },
      { c: 'Vínculo (OS, cliente, funcionário)', t: 'texto', rotulo: 'Vínculo (ex.: OS-0012)' },
      { c: 'Confirmado por', t: 'info', sistema: true }, { c: 'Confirmado em', t: 'info', sistema: true },
      { c: 'Forma de pagamento', t: 'lista', opcoes: ['PIX', 'Boleto', 'Cartão', 'Dinheiro', 'Transferência'] },
      { c: 'Linha digitável', t: 'texto', rotulo: 'Linha digitável do boleto' },
      { c: 'Comprovante', t: 'link', sistema: true }, { c: 'Recibo', t: 'link', sistema: true }, { c: 'Boleto', t: 'link', sistema: true }
    ]
  },
  FIXAS: {
    planilha: 'FINANCEIRO', aba: 'FIXAS', id: 'ID (sistema)', chave: 'Despesa fixa', titulo: 'Despesa fixa', novo: 'Nova despesa fixa',
    card: { titulo: 'Despesa fixa', sub: ['Dia'], valor: 'Valor', meses: true, anexo: ['Comprovantes'] },
    ordem: { campo: 'Dia' },
    campos: [
      { c: 'Despesa fixa', t: 'texto', obrig: true }, { c: 'Valor', t: 'dinheiro', obrig: true }, { c: 'Dia', t: 'numero', rotulo: 'Dia do vencimento' },
      { c: 'Jan', t: 'bool', mes: 1 }, { c: 'Fev', t: 'bool', mes: 2 }, { c: 'Mar', t: 'bool', mes: 3 }, { c: 'Abr', t: 'bool', mes: 4 },
      { c: 'Mai', t: 'bool', mes: 5 }, { c: 'Jun', t: 'bool', mes: 6 }, { c: 'Jul', t: 'bool', mes: 7 }, { c: 'Ago', t: 'bool', mes: 8 },
      { c: 'Set', t: 'bool', mes: 9 }, { c: 'Out', t: 'bool', mes: 10 }, { c: 'Nov', t: 'bool', mes: 11 }, { c: 'Dez', t: 'bool', mes: 12 },
      { c: 'Pago no ano', t: 'info', tipoInfo: 'dinheiro' }, { c: 'Última baixa', t: 'info', sistema: true }, { c: 'Comprovantes', t: 'link', sistema: true }
    ]
  },
  RESERVA: {
    planilha: 'FINANCEIRO', aba: 'RESERVA', id: 'ID (sistema)', chave: 'Valor', titulo: 'Movimento da reserva', novo: 'Guardar ou tirar',
    card: { titulo: 'Guardei ou tirei', data: 'Data', valor: 'Valor', sub: ['Saldo da reserva'], anexo: ['Comprovante'] },
    ordem: { campo: 'Data', desc: true },
    filtros: ['Guardei ou tirei'],
    campos: [
      { c: 'Data', t: 'data', padrao: 'hoje', obrig: true },
      { c: 'Guardei ou tirei', t: 'lista', opcoes: ['Guardei', 'Tirei'], obrig: true },
      { c: 'Valor', t: 'dinheiro', obrig: true },
      { c: 'Saldo da reserva', t: 'info', tipoInfo: 'dinheiro' }, { c: 'Comprovante', t: 'link', sistema: true }
    ]
  },
  FUNCIONARIOS: {
    planilha: 'EQUIPE', aba: 'FUNCIONÁRIOS', id: 'ID', chave: 'Nome', titulo: 'Funcionário', novo: 'Novo funcionário',
    card: { titulo: 'Nome', sub: ['Função', 'Forma de pagamento', 'Telefone'], selo: 'Ativo?' },
    ordem: { campo: 'Nome' },
    filtros: ['Ativo?', 'Forma de pagamento', 'Função'],
    campos: [
      { c: 'Nome', t: 'texto', obrig: true }, { c: 'Função', t: 'texto' }, { c: 'Telefone', t: 'texto', tel: true },
      { c: 'CPF', t: 'texto' }, { c: 'Admissão', t: 'data' },
      { c: 'Ativo?', t: 'lista', opcoes: ['Sim', 'Não'], padrao: 'Sim' },
      { c: 'Forma de pagamento', t: 'lista', opcoes: ['Mensal', 'Diária'], padrao: 'Diária' },
      { c: 'Valor da diária', t: 'dinheiro' },
      { c: 'Salário base', t: 'dinheiro', rotulo: 'Salário base (mensal)' },
      { c: 'Jornada diária (h)', t: 'numero', padrao: 8 },
      { c: 'Valor hora extra', t: 'dinheiro', rotulo: 'Valor da hora extra (em branco = calcula pelo salário)' },
      { c: 'Valor da hora', t: 'info', tipoInfo: 'dinheiro' },
      { c: 'Login no sistema', t: 'info', sistema: true },
      { c: 'Observações', t: 'area' }
    ]
  },
  PRESENCA: {
    planilha: 'EQUIPE', aba: 'PRESENÇA', id: 'ID registro', chave: 'Funcionário', titulo: 'Presença', novo: 'Lançar presença',
    card: { titulo: 'Funcionário', data: 'Data', sub: ['Horas extras', 'Observação', 'Marcado por'], selo: 'Presença', valor: 'Total do dia' },
    ordem: { campo: 'Data', desc: true },
    filtros: ['Funcionário', 'Presença'], mes: 'Data',
    campos: [
      { c: 'Data', t: 'data', padrao: 'hoje', obrig: true },
      { c: 'Funcionário', t: 'lista', opcoes: 'TAB:FUNCIONARIOS:Nome', obrig: true },
      { c: 'Presença', t: 'lista', opcoes: ['Presente', 'Meia diária', 'Falta', 'Folga'], padrao: 'Presente' },
      { c: 'Horas extras', t: 'numero', rotulo: 'Horas extras (ex.: 1,5)' },
      { c: 'Valor da diária', t: 'dinheiro' }, { c: 'Valor hora extra', t: 'dinheiro' },
      { c: 'Total do dia', t: 'info', tipoInfo: 'dinheiro' },
      { c: 'Observação', t: 'texto' }, { c: 'Marcado por', t: 'info', sistema: true }
    ]
  },
  PONTO: {
    planilha: 'EQUIPE', aba: 'PONTO', id: 'ID registro', chave: 'Funcionário', titulo: 'Registro de ponto', novo: 'Lançar ponto',
    card: { titulo: 'Funcionário', data: 'Data', sub: ['Entrada', 'Saída', 'Horas trabalhadas', 'Horas extras'], selo: 'Situação' },
    ordem: { campo: 'Data', desc: true },
    filtros: ['Funcionário', 'Situação'], mes: 'Data',
    campos: [
      { c: 'Data', t: 'data', padrao: 'hoje', obrig: true },
      { c: 'Funcionário', t: 'lista', opcoes: 'TAB:FUNCIONARIOS:Nome', obrig: true },
      { c: 'Entrada', t: 'hora' }, { c: 'Saída almoço', t: 'hora' }, { c: 'Volta almoço', t: 'hora' }, { c: 'Saída', t: 'hora' },
      { c: 'Situação', t: 'lista', opcoes: ['Normal', 'Falta', 'Atestado', 'Folga', 'Feriado', 'Férias'], padrao: 'Normal' },
      { c: 'Horas trabalhadas', t: 'info', tipoInfo: 'hora' }, { c: 'Horas extras', t: 'info', tipoInfo: 'hora' },
      { c: 'Observação', t: 'texto' }, { c: 'Origem', t: 'info' }
    ]
  }
};
