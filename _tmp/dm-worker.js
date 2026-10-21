// DM automática por comentário (Instagram @sergiojcjr) — Cloudflare Worker.
//
// Quem comenta a PALAVRA de um post recebe UMA mensagem privada com o link de afiliado
// ("Private Reply" da API oficial do Instagram). Regras conferidas em 21/10/2026:
// - Meta, Private Replies: uma mensagem por comentário, enviada em até 7 dias; nova mensagem
//   só se a pessoa responder (dentro de 24 h). https://developers.facebook.com/docs/instagram-platform/private-replies/
// - Amazon Associados BR, Políticas do Programa, Limitações Promocionais, cláusula 4: links em
//   "mensagens diretas de seus Sites de mídia social" só quando "solicitadas" pelo cliente.
//   Comentar a palavra é o pedido. https://associados.amazon.com.br/help/operating/policies
//
// Segredos (wrangler secret put): IG_APP_SECRET e/ou META_APP_SECRET, IG_TOKEN (token de longa duração), VERIFY_TOKEN.
// Nada de chave neste arquivo. Configuração das palavras: KV "DM", chave "palavras" (ver README).

const VERSAO = (env) => env.GRAPH_VERSION || "v23.0";

// Política de privacidade exigida pela Meta para o app (modo publicado). Dado mínimo, LGPD.
const PRIVACIDADE = `<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacidade — DM automática @sergiojcjr</title>
<body style="font-family:system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 16px;line-height:1.5;color:#14211F;background:#F4F1EA">
<h1>Política de privacidade</h1>
<p>Este serviço é usado apenas pelo perfil <b>@sergiojcjr</b> no Instagram. Quando você comenta a palavra indicada num post, ele envia a você, uma única vez, uma mensagem privada com o link pedido, pela API oficial do Instagram (Meta).</p>
<h2>O que é tratado</h2>
<ul><li>O texto do seu comentário e o identificador do comentário, só para conferir a palavra e responder.</li>
<li>Um código irreversível (hash) do seu identificador no Instagram, guardado por até 7 dias, só para não mandar a mesma mensagem duas vezes.</li>
<li>Contagens diárias sem identificação (quantas mensagens foram enviadas por palavra), guardadas por até 90 dias.</li></ul>
<p>Nome de usuário, fotos e conteúdo das conversas não são guardados. Nada é vendido nem compartilhado com terceiros, além da própria Meta, que entrega a mensagem.</p>
<h2>Base legal e direitos</h2>
<p>O tratamento atende ao seu pedido (o comentário com a palavra), conforme a Lei 13.709/2018 (LGPD). Para pedir a exclusão dos dados ou tirar dúvidas, mande mensagem direta para @sergiojcjr no Instagram.</p>
<p>Última atualização: 21/10/2026.</p></body></html>`;
const SETE_DIAS = 7 * 24 * 3600;

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === "/privacidade") return new Response(PRIVACIDADE, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    if (url.pathname !== "/webhook") return new Response("ok", { status: 200 });

    // 1) Verificação do webhook (a Meta chama uma vez, ao assinar)
    if (req.method === "GET") {
      const ok = url.searchParams.get("hub.mode") === "subscribe" &&
        url.searchParams.get("hub.verify_token") === env.VERIFY_TOKEN;
      return ok ? new Response(url.searchParams.get("hub.challenge"), { status: 200 })
                : new Response("forbidden", { status: 403 });
    }
    if (req.method !== "POST") return new Response("method", { status: 405 });

    // 2) Assinatura: só aceita aviso assinado pela Meta com o segredo do app
    const corpo = await req.text();
    // A Meta assina com a chave secreta do app; aceita a do app do Instagram ou a do app da Meta
    // (a documentação não deixa claro qual vale para o login do Instagram; conferido na prática em 21/10/2026).
    const sig = req.headers.get("X-Hub-Signature-256");
    let valida = false;
    for (const seg of [env.IG_APP_SECRET, env.META_APP_SECRET]) if (seg && (await assinaturaValida(corpo, sig, seg))) valida = true;
    if (!valida) { ctx.waitUntil(contar(env, "assinatura_invalida")); return new Response("assinatura", { status: 401 }); }
    // Responde rápido (a Meta pede) e processa em segundo plano
    ctx.waitUntil(processar(JSON.parse(corpo), env).catch((e) => contar(env, "erro_interno", String(e).slice(0, 120))));
    return new Response("EVENT_RECEIVED", { status: 200 });
  },

  // 3) Renova o token de longa duração (vale 60 dias) toda semana
  async scheduled(_ev, env) {
    const atual = await token(env);
    const r = await fetch(`https://graph.instagram.com/refresh_access_token?grant_type=ig_refresh_token&access_token=${encodeURIComponent(atual)}`);
    const j = await r.json();
    if (j.access_token) {
      await env.DM.put("token", j.access_token);
      await contar(env, "token_renovado");
    } else {
      await contar(env, "token_erro", JSON.stringify(j.error || j).slice(0, 200));
    }
  },
};

async function processar(dados, env) {
  if (dados.object !== "instagram") return;
  const palavras = JSON.parse((await env.DM.get("palavras")) || "{}");
  for (const entrada of dados.entry || []) {
    const contaId = entrada.id;
    for (const mud of entrada.changes || []) {
      if (mud.field !== "comments") continue;
      const v = mud.value || {};
      const comentarioId = v.comment_id || v.id;
      const autorId = v.from && v.from.id;
      if (!comentarioId || !autorId || autorId === contaId) continue; // ignora o próprio perfil
      if (v.parent_id) continue;                                      // ignora resposta a comentário

      const chave = acharPalavra(v.text || "", palavras, v.media && v.media.id);
      if (!chave) continue;
      const cfg = palavras[chave];

      // Uma vez por comentário e, no máximo, uma DM por pessoa por palavra a cada 7 dias
      if (await env.DM.get(`c:${comentarioId}`)) continue;
      const marcaPessoa = `u:${await hash(autorId)}:${chave}`;
      if (await env.DM.get(marcaPessoa)) { await contar(env, `repetido:${chave}`); continue; }
      await env.DM.put(`c:${comentarioId}`, "1", { expirationTtl: SETE_DIAS + 86400 });

      const okDm = await enviarDm(env, contaId, comentarioId, textoDm(cfg));
      if (okDm.ok) {
        await env.DM.put(marcaPessoa, "1", { expirationTtl: SETE_DIAS });
        await contar(env, `dm:${chave}`);
        if (cfg.responder_publico !== false) await responderPublico(env, comentarioId);
      } else {
        await contar(env, `dm_erro:${chave}`, okDm.erro);
      }
    }
  }
}

// Palavra inteira, sem diferença de maiúscula ou acento. Se a palavra tiver "midias",
// vale só nesses posts; sem "midias", vale em qualquer post.
export function acharPalavra(texto, palavras, midiaId) {
  const norm = (s) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toUpperCase();
  const t = ` ${norm(texto).replace(/[^A-Z0-9]+/g, " ")} `;
  for (const [k, cfg] of Object.entries(palavras)) {
    if (cfg.ativo === false) continue;
    if (Array.isArray(cfg.midias) && cfg.midias.length && !cfg.midias.includes(midiaId)) continue;
    if (t.includes(` ${norm(k)} `)) return k;
  }
  return null;
}

// Texto da DM: identifica a publicidade logo no início (regra do projeto) e não fixa preço.
export function textoDm(cfg) {
  return cfg.texto ||
    `Oi! Aqui está o link do ${cfg.produto}: ${cfg.link}\n\n` +
    `É link de afiliado: se você comprar por ele, eu recebo uma comissão. ` +
    `O preço de hoje está na página do produto.`;
}

async function enviarDm(env, contaId, comentarioId, texto) {
  const r = await fetch(`https://graph.instagram.com/${VERSAO(env)}/${contaId}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${await token(env)}` },
    body: JSON.stringify({ recipient: { comment_id: comentarioId }, message: { text: texto } }),
  });
  if (r.ok) return { ok: true };
  return { ok: false, erro: (await r.text()).slice(0, 200) };
}

const RESPOSTAS = ["Te mandei no direct 📩", "Enviei no seu direct 📩", "Olha o direct 📩"];
async function responderPublico(env, comentarioId) {
  const msg = RESPOSTAS[Math.floor(Math.random() * RESPOSTAS.length)];
  const r = await fetch(`https://graph.instagram.com/${VERSAO(env)}/${comentarioId}/replies`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${await token(env)}` },
    body: JSON.stringify({ message: msg }),
  });
  if (!r.ok) await contar(env, "resposta_publica_erro", (await r.text()).slice(0, 200));
}

async function token(env) { return (await env.DM.get("token")) || env.IG_TOKEN; }

// Contagem por dia, sem guardar nome nem id de quem comentou (LGPD: dado mínimo)
async function contar(env, evento, detalhe) {
  const dia = new Date().toISOString().slice(0, 10);
  const k = `stats:${dia}:${evento}`;
  const n = parseInt((await env.DM.get(k)) || "0", 10) + 1;
  await env.DM.put(k, String(n), { expirationTtl: 90 * 86400 });
  if (detalhe) await env.DM.put(`ultimo:${evento}`, `${new Date().toISOString()} ${detalhe}`, { expirationTtl: 90 * 86400 });
}

async function hash(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function assinaturaValida(corpo, cabecalho, segredo) {
  if (!cabecalho || !segredo || !cabecalho.startsWith("sha256=")) return false;
  const chave = await crypto.subtle.importKey("raw", new TextEncoder().encode(segredo),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", chave, new TextEncoder().encode(corpo)));
  const hex = [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
  const esperado = cabecalho.slice(7);
  if (hex.length !== esperado.length) return false;
  let dif = 0;
  for (let i = 0; i < hex.length; i++) dif |= hex.charCodeAt(i) ^ esperado.charCodeAt(i);
  return dif === 0;
}
