/*
 * Dados de DEMONSTRAÇÃO da prévia (todos inventados: nomes, CNPJs e telefones não existem).
 * Roda o código de verdade do servidor (gas/*.gs através do simulador teste/mock.js),
 * então tudo que aparece na prévia foi criado pelas mesmas funções do sistema.
 * As datas são relativas a hoje, para a demonstração nunca ficar "velha".
 */
window.semear = function semear(ctx, PLAN) {
  // a cópia de teste das planilhas tem poucas linhas com código em algumas abas: acrescenta mais (só na memória)
  const ampliar = (pl, aba, col, pre, dig, ate) => {
    const a = PLAN[pl][aba], i = a.m[0].indexOf(col), ids = a.m.slice(1).map(r => String(r[i] || '')).filter(Boolean);
    for (let n = ids.length + 1; n <= ate; n++) { const r = a.m[0].map(() => ''); r[i] = pre + String(n).padStart(dig, '0'); a.m.push(r); }
  };
  ampliar('FINANCEIRO', 'MOVIMENTO', 'ID (sistema)', 'MOV-', 5, 300);
  ampliar('FINANCEIRO', 'FIXAS', 'ID (sistema)', 'FIX-', 3, 40);
  ampliar('FINANCEIRO', 'RESERVA', 'ID (sistema)', 'RES-', 4, 60);
  const silencio = console.log; let temp = '';
  console.log = (...a) => { const m = a.join(' ').match(/temporária: (\S+)/); if (m) temp = m[1]; };
  ctx.configuracaoInicial();
  console.log = silencio;
  let T = ctx.login('admin', temp).token; ctx.chamarApi('trocarSenha', T, { atual: temp, nova: 'senha123' });
  T = ctx.login('admin', 'senha123').token;
  const A = (a, d) => { const r = ctx.chamarApi(a, T, d); if (!r.ok) console.warn('[demo] ' + a + ': ' + r.erro); return r.dados || {}; };
  const hoje = new Date(), dia = n => { const d = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate() + n); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };
  const mes = n => { const d = new Date(hoje.getFullYear(), hoje.getMonth() + n, 1); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0'); };

  // ---- dados da empresa (responsável técnico de exemplo)
  const dados = ctx.dadosLer_ ? ctx.dadosLer_() : [];
  const val = { 'Responsável técnico': 'Eng. João Pereira (exemplo)', 'Registro do responsável técnico': 'CREA-MG 000000/D', 'WhatsApp do contador': '5534990000001', 'Instagram': '@ngarcondicionadonilton' };
  A('dadosSalvar', { itens: dados.filter(x => val[x.campo] !== undefined).map(x => ({ linha: x.linha, valor: val[x.campo] })) });

  // ---- equipe e usuários
  A('salvar', { tabela: 'FUNCIONARIOS', valores: { 'Nome': 'Nilton', 'Função': 'Técnico', 'Técnico de campo?': 'Sim', 'Forma de pagamento': 'Diária', 'Valor da diária': 180, 'Valor hora extra': 30, 'Ativo?': 'Sim', 'Telefone': '34 99999-0000' } });
  A('salvar', { tabela: 'FUNCIONARIOS', valores: { 'Nome': 'Carlos Henrique', 'Função': 'Ajudante', 'Técnico de campo?': 'Não', 'Forma de pagamento': 'Diária', 'Valor da diária': 120, 'Ativo?': 'Sim' } });
  A('salvar', { tabela: 'FUNCIONARIOS', valores: { 'Nome': 'Thais Araújo', 'Função': 'Escritório', 'Forma de pagamento': 'Mensal', 'Salário base': 2200, 'Ativo?': 'Sim' } });
  const usuario = (login, nome, perfil, func) => {
    const r = ctx.chamarApi('usuarioSalvar', T, { novo: true, login, nome, perfil, extras: [], tecnico: '', funcionario: func, ativo: true });
    const t0 = r.dados.senhaTemporaria, tk = ctx.login(login, t0).token; ctx.chamarApi('trocarSenha', tk, { atual: t0, nova: 'senha123' });
  };
  usuario('thais', 'Thais Araújo', 'Administrador', 'Thais Araújo');
  usuario('nilton', 'Nilton', 'Técnico', 'Nilton');
  A('presencaSalvar', { data: dia(-1), itens: [{ nome: 'Nilton', presenca: 'Presente', he: '2' }, { nome: 'Carlos Henrique', presenca: 'Presente' }] });

  // ---- clientes
  const cli = (v) => A('salvar', { tabela: 'CLIENTES', valores: Object.assign({ 'Cidade': 'Uberlândia' }, v) });
  cli({ 'Nome / razão social': 'Hospital Vida Plena LTDA', 'CPF / CNPJ': '12.345.678/0001-90', 'Telefone': '34 3333-1111', 'Endereço': 'Av. das Palmeiras, 1500', 'Bairro': 'Centro', 'Tipo': 'Contrato PMOC', 'Pessoa': 'Jurídica', 'Gênero': 'Feminino', 'Contato no local': 'Cássia Melo' });
  cli({ 'Nome / razão social': 'Clínica Bem Estar', 'CPF / CNPJ': '11.222.333/0001-44', 'Telefone': '34 99876-5432', 'Endereço': 'Rua dos Ipês, 230', 'Bairro': 'Santa Mônica', 'Tipo': 'Empresa', 'Pessoa': 'Jurídica', 'Gênero': 'Feminino', 'Contato no local': 'Renata Alves' });
  cli({ 'Nome / razão social': 'Aldo Ferreira', 'CPF / CNPJ': '123.456.789-09', 'Telefone': '34 98888-7777', 'Endereço': 'Rua Goiás, 45', 'Bairro': 'Fundinho', 'Tipo': 'Residencial', 'Pessoa': 'Física', 'Gênero': 'Masculino' });
  cli({ 'Nome / razão social': 'Padaria Pão Quente', 'CPF / CNPJ': '98.765.432/0001-10', 'Telefone': '34 98888-2222', 'Endereço': 'Av. Brasil, 900', 'Bairro': 'Pacaembu', 'Tipo': 'Empresa', 'Pessoa': 'Jurídica', 'Gênero': 'Masculino', 'Contato no local': 'Sérgio' });

  // ---- estoque
  ['Gás R410A|Gás refrigerante|kg|8|90', 'Gás R32|Gás refrigerante|kg|2|95', 'Tubo de cobre 1/4|Tubulação e isolamento|m|40|14', 'Tubo de cobre 3/8|Tubulação e isolamento|m|25|19',
   'Fita PVC|Tubulação e isolamento|un|12|6', 'Capacitor 35uF|Peças e componentes|un|2|28', 'Cabo PP 3x2,5|Elétrica|m|50|7', 'Filtro de ar universal|Peças e componentes|un|15|22'].forEach(x => {
    const [i, c, u, q, v] = x.split('|'); A('salvar', { tabela: 'ESTOQUE', valores: { 'Item': i, 'Categoria': c, 'Unidade': u, 'Quantidade': +q, 'Mínimo': 3, 'Valor unitário': +v } });
  });

  // ---- financeiro: seis meses de movimento, contas a pagar/receber, fixas e reserva
  for (let m = -5; m <= 0; m++) {
    const p = mes(m), base = 3200 + (m + 5) * 350;
    A('salvar', { tabela: 'MOVIMENTO', valores: { 'Data': p + '-08', 'Entrada ou saída': 'Entrada', 'Valor': base, 'Pago?': true, 'Descrição': 'Serviços do período', 'Categoria': 'Serviço', 'Forma de pagamento': 'PIX' } });
    A('salvar', { tabela: 'MOVIMENTO', valores: { 'Data': p + '-10', 'Entrada ou saída': 'Entrada', 'Valor': 1800, 'Pago?': true, 'Descrição': 'Mensalidade PMOC · Hospital Vida Plena', 'Categoria': 'Contrato', 'Forma de pagamento': 'Boleto' } });
    A('salvar', { tabela: 'MOVIMENTO', valores: { 'Data': p + '-15', 'Entrada ou saída': 'Saída', 'Valor': 900 + (m + 5) * 120, 'Pago?': true, 'Descrição': 'Material e peças', 'Categoria': 'Material e peças', 'Forma de pagamento': 'Cartão' } });
    A('salvar', { tabela: 'MOVIMENTO', valores: { 'Data': p + '-18', 'Entrada ou saída': 'Saída', 'Valor': 420, 'Pago?': true, 'Descrição': 'Combustível', 'Categoria': 'Combustível', 'Forma de pagamento': 'Cartão' } });
  }
  A('salvar', { tabela: 'MOVIMENTO', valores: { 'Data': dia(2), 'Entrada ou saída': 'Saída', 'Valor': 380, 'Pago?': false, 'Descrição': 'Boleto fornecedor de gás', 'Categoria': 'Material e peças' } });
  A('salvar', { tabela: 'MOVIMENTO', valores: { 'Data': dia(5), 'Entrada ou saída': 'Entrada', 'Valor': 1800, 'Pago?': false, 'Descrição': 'Mensalidade PMOC · Hospital Vida Plena', 'Categoria': 'Contrato', 'Forma de pagamento': 'Boleto', 'Vínculo (OS, cliente, funcionário)': 'Hospital Vida Plena LTDA' } });
  const mm = ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Jul', 'Ago', 'Set', 'Out', 'Nov', 'Dez'], pagos = {}; mm.slice(0, hoje.getMonth()).forEach(m => pagos[m] = true);
  A('salvar', { tabela: 'FIXAS', valores: Object.assign({ 'Despesa fixa': 'Aluguel do galpão', 'Valor': 1500, 'Dia': 5 }, pagos) });
  A('salvar', { tabela: 'FIXAS', valores: Object.assign({ 'Despesa fixa': 'Internet e telefone', 'Valor': 150, 'Dia': 12 }, pagos) });
  A('salvar', { tabela: 'FIXAS', valores: Object.assign({ 'Despesa fixa': 'Honorários do contador', 'Valor': 450, 'Dia': 20 }, pagos) });
  A('salvar', { tabela: 'RESERVA', valores: { 'Data': mes(-2) + '-28', 'Guardei ou tirei': 'Guardei', 'Valor': 1500 } });
  A('salvar', { tabela: 'RESERVA', valores: { 'Data': mes(-1) + '-28', 'Guardei ou tirei': 'Guardei', 'Valor': 1000 } });

  // ---- orçamentos: um aberto (residencial) e um avulso aprovado (com OS e recibo)
  A('orcamentoSalvar', { valores: { 'Cliente': 'Aldo Ferreira', 'Tipo': 'Serviço avulso', 'Observações': 'Instalação na suíte do 2º andar.' }, itens: [{ servico: 'Instalação de split 12.000 BTU', descricao: 'Até 3 m de tubulação', qtd: 1, valor: 650 }, { servico: 'Metro adicional de tubulação', qtd: 2, valor: 85 }] });
  const oPad = A('orcamentoSalvar', { valores: { 'Cliente': 'Padaria Pão Quente', 'Tipo': 'Serviço avulso' }, itens: [{ servico: 'Higienização completa', descricao: 'Split 18.000 BTU do salão', qtd: 2, valor: 180 }] }).id;
  A('fecharNegocio', { id: oPad, os: { abrir: true, tecnico: 'Nilton', data: dia(1) }, cobrar: { lancar: true, data: dia(1) }, recebido: { sim: true, valor: 180 }, forma: 'PIX' });

  // ---- PMOC 1: hospital com 2 fan coils e 1 split, contrato há 2 meses, mês atual já registrado (relatório pronto)
  const eq = (c, local, tipo, marca, cap, extra) => A('salvar', { tabela: 'EQUIPAMENTOS', valores: Object.assign({ 'Cliente': c, 'Local / setor': local, 'Tipo': tipo, 'Marca': marca, 'Capacidade': cap }, extra || {}) }).id;
  const h1 = eq('Hospital Vida Plena LTDA', 'Estoque', 'Fan coil (modelo HBC)', 'Coldex Tosi', '12,5 TR', { 'Modelo': 'FCT-125', 'Nº de série': 'OF 1012', 'Área (m²)': 120, 'Ocupantes': 10 });
  const h2 = eq('Hospital Vida Plena LTDA', 'Estoque', 'Fan coil (modelo HBC)', 'Coldex Tosi', '7,5 TR', { 'Modelo': 'FCT-75', 'Nº de série': 'OF 455', 'Área (m²)': 80, 'Ocupantes': 6 });
  const h3 = eq('Hospital Vida Plena LTDA', 'Recepção', 'Split hi-wall (de parede)', 'LG', '24.000 BTU', { 'Área (m²)': 40, 'Ocupantes': 15 });
  const oH = A('orcamentoSalvar', { valores: { 'Cliente': 'Hospital Vida Plena LTDA', 'Tipo': 'Contrato PMOC' }, itens: [{ servico: 'PMOC mensal', descricao: '3 equipamentos', qtd: 1, valor: 1800 }] }).id;
  const fH = A('fecharNegocio', { id: oH, contrato: { inicio: mes(-2) + '-01', dia: 10, meses: 12 }, os: { abrir: true, tecnico: 'Nilton', data: dia(-3) }, equipamentos: [h1, h2, h3], cobrar: { lancar: false }, forma: 'Boleto' });
  if (fH.contrato) {
    A('salvar', { tabela: 'CONTRATOS', id: fH.contrato.id, valores: { 'ART / TRT': 'MG20260000001 (exemplo)' } });
    const ck = A('pmocChecklist', { contrato: fH.contrato.id, mes: mes(0) });
    const env = (ck.equipamentos || []).map(e => ({ id: e.id, itens: e.itens.map((i, n) => i.resp === 'Medição' ? { id: i.id, medicao: String(12 + (n % 9)) + ',5' } : { id: i.id, resultado: (e.id === h1 && n === 3) ? 'NOK' : 'OK', obs: (e.id === h1 && n === 3) ? 'Correia desgastada: trocar na próxima visita' : '' }) }));
    A('pmocRegistrar', { contrato: fH.contrato.id, mes: mes(0), os: fH.os, equipamentos: env, tecnico: 'Nilton' });
    A('salvar', { tabela: 'SERVICOS', id: fH.os, valores: { 'Situação': 'Concluído', 'Concluído em': dia(-3) } });
  }

  // ---- PMOC 2: clínica, contrato deste mês, visita de hoje do Nilton (checklist para fazer na demonstração)
  const c1 = eq('Clínica Bem Estar', 'Recepção', 'Split hi-wall (de parede)', 'Samsung', '18.000 BTU', { 'Área (m²)': 30, 'Ocupantes': 8 });
  const c2 = eq('Clínica Bem Estar', 'Sala de exames', 'Split piso-teto', 'Carrier', '36.000 BTU', { 'Área (m²)': 35, 'Ocupantes': 6 });
  const oC = A('orcamentoSalvar', { valores: { 'Cliente': 'Clínica Bem Estar', 'Tipo': 'Contrato PMOC' }, itens: [{ servico: 'PMOC mensal', qtd: 2, valor: 190 }] }).id;
  A('fecharNegocio', { id: oC, contrato: { inicio: mes(0) + '-01', dia: 10, meses: 12 }, os: { abrir: true, tecnico: 'Nilton', data: dia(0) }, equipamentos: [c1, c2], cobrar: { lancar: true, data: dia(7) }, forma: 'PIX' });

  // ---- serviço corretivo de hoje e contatos do site
  A('salvar', { tabela: 'SERVICOS', valores: { 'Cliente': 'Aldo Ferreira', 'Tipo': 'Manutenção corretiva', 'Descrição': 'Split do quarto pingando água', 'Técnico': 'Nilton', 'Agendado para': dia(0), 'Situação': 'Agendado', 'Valor': 220 } });
  ctx.doPost({ postData: { contents: JSON.stringify({ site: 'ng', tipo: 'formulario', nome: 'Ana Paula', tel: '34 99123-4567', serv: 'PMOC', msg: 'Clínica com 12 aparelhos, preciso de orçamento' }) } });
  ctx.doPost({ postData: { contents: JSON.stringify({ site: 'ng', tipo: 'whatsapp', botao: 'Pedir orçamento' }) } });
  try { ctx.descarregarRequisicoes_(); } catch (e) { }
};
