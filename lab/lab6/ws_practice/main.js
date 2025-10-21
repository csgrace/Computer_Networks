console.log("main.js loaded");
alert("main.js 现在真的加载了！");

// 日志 + 健壮性增强版
const timers = [];
let danmaku = null;

// 注意：如果不是在运行 Python 的同一台机器上打开页面，请把 127.0.0.1 改成 Python 机器的局域网 IP
const ws = new WebSocket("ws://127.0.0.1:8765");

ws.onopen = function () {
  console.log("[WS] open");
};

ws.onerror = function (e) {
  console.error("[WS] error", e);
};

ws.onclose = function (e) {
  console.warn("[WS] close", e);
};

ws.onmessage = function (e) {
  console.log("[WS] message:", e.data);
  danmaku = e.data;
  const $dom = createDanmaku(danmaku);
  animateDanmaku($dom); // 使用 rAF 动画，避免定时器误差
};

$(".send").on("click", function () {
  const msg = $("#danmakutext").val();
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.warn("[WS] not open, cannot send");
    return;
  }
  if (!msg || !msg.trim()) {
    return; // 空消息不发
  }
  ws.send(msg);
  $("#danmakutext").val("");
});

function createDanmaku(text) {
  const $screen = $(".screen_container");

  // 使用 .text() 防止消息里有 HTML 导致 DOM 结构异常
  const $dom = $("<div class='bullet'></div>").text(text);

  // 先追加再算高度，避免 top 计算不准
  $dom.css({
    position: "absolute",
    color: "rgb(255,255,255)",
    "font-size": "20px",
    left: $screen.width() + "px", // 从容器最右侧之外一点开始
    top: "0px"
  });
  $screen.append($dom);

  // 现在算出一个安全的 top，保证弹幕不会被下边界完全遮住
  const maxTop = Math.max(0, $screen.height() - $dom.outerHeight());
  const top = Math.floor(Math.random() * (maxTop + 1));
  $dom.css("top", top + "px");

  return $dom;
}

// 使用 requestAnimationFrame 做位移动画
function animateDanmaku($dom) {
  const $screen = $(".screen_container");
  const screenLeft = $screen.offset().left;

  let left = $dom.offset().left - screenLeft; // 相对容器的 left
  const speed = 120; // px/s，可按需调整
  let last = performance.now();

  function tick(now) {
    const dt = (now - last) / 1000;
    last = now;

    left -= speed * dt;
    $dom.css("left", left + "px");

    if ($dom.offset().left + $dom.width() < screenLeft) {
      $dom.remove();
      return;
    }
    requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}