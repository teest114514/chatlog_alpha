(() => {
    'use strict';

    const apiBase = '/api/v1/send-debug';
    let activeJobID = '';
    let activeMessageType = '';
    let activeImageUsed = false;
    let activeOperation = '';
    let pollTimer = null;
    let environmentReady = false;
    let startInFlight = false;
    let switchInFlight = false;
    let enqueueTail = Promise.resolve();

    const byID = (id) => document.getElementById(id);
    const value = (id) => String(byID(id)?.value || '').trim();

    function escapeHTML(input) {
        return String(input ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }

    function setHidden(element, hidden) {
        if (!element) return;
        element.classList.toggle('hidden', !!hidden);
    }

    function setStep(index, state) {
        const element = byID(`send-debug-step-${index}`);
        if (!element) return;
        element.classList.remove('active', 'done', 'failed');
        if (state) element.classList.add(state);
    }

    function resetSteps() {
        for (let i = 1; i <= 4; i += 1) setStep(i, '');
    }

    function setState(text, kind = '') {
        const element = byID('send-debug-state');
        if (!element) return;
        element.textContent = text;
        element.classList.remove('text-success', 'text-danger', 'text-warning');
        if (kind) element.classList.add(`text-${kind}`);
    }

    async function readJSON(response) {
        const text = await response.text();
        if (!text) return {};
        try {
            return JSON.parse(text);
        } catch (_) {
            return { error: text };
        }
    }

    window.sendDebugSyncForm = function sendDebugSyncForm() {
        const targetType = value('send-debug-target-type') || 'private';
        const messageType = value('send-debug-message-type') || 'text';
        const isGroup = targetType === 'group';
        const isImage = messageType === 'image';

        setHidden(byID('send-debug-private-target-row'), isGroup);
        setHidden(byID('send-debug-group-target-row'), !isGroup);
        document.querySelectorAll('.send-debug-group-only').forEach((node) => setHidden(node, !isGroup || isImage));
        document.querySelectorAll('.send-debug-text-field').forEach((node) => setHidden(node, isImage));
        document.querySelectorAll('.send-debug-image-field').forEach((node) => setHidden(node, !isImage));
        setHidden(byID('send-debug-sender-row'), !isImage);
        const releaseButton = byID('send-debug-release-btn');
        const sendButton = byID('send-debug-send-btn');
        if (releaseButton && !activeJobID) {
            releaseButton.textContent = isImage ? '结束图片 Session（重启微信）' : '释放 Frida';
        }
        if (sendButton && activeJobID && !switchInFlight) {
            sendButton.textContent = `发送${isImage ? '图片' : '文本'}`;
        }

        if (environmentReady && !activeJobID) {
            setStep(2, 'active');
        }
    };

    window.sendDebugCheckEnvironment = async function sendDebugCheckEnvironment() {
        const box = byID('send-debug-environment');
        environmentReady = false;
        resetSteps();
        setStep(1, 'active');
        setState('正在检查');
        if (box) box.innerHTML = '<div class="analytics-empty">正在检查微信版本、进程、Python 和 Frida...</div>';
        try {
            const response = await fetch(`${apiBase}/environment`, { cache: 'no-store' });
            const data = await readJSON(response);
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            environmentReady = !!data.supported;
            if (box) {
                const entries = [
                    ['平台', `${data.platform || '-'} / ${data.architecture || '-'}`],
                    ['微信版本', `${data.wechat_version || '-'} (${data.wechat_build || '-'})`],
                    ['Hook Profile', `${data.profile_version || '-'} · ${data.profile_matched ? '匹配' : '不匹配'}`],
                    ['微信进程', data.wechat_running ? `运行中 · PID ${data.wechat_pid}` : '未运行'],
                    ['Python', data.python_path || '未找到'],
                    ['Frida', data.frida_version || '不可用'],
                    ['管理员授权', data.elevation_capable ? '可自动弹窗' : '不可用'],
                    ['资源 SHA256', data.dylib_sha256 ? `${data.dylib_sha256.slice(0, 16)}…` : '-'],
                ];
                box.innerHTML = entries.map(([label, val]) => `
                    <div class="send-debug-env-item">
                        <span>${escapeHTML(label)}</span>
                        <strong>${escapeHTML(val)}</strong>
                    </div>`).join('') + (data.reason ? `
                    <div class="send-debug-env-item" style="grid-column:1/-1;border-color:#fca5a5;background:#fff1f2;">
                        <span>阻断原因</span><strong class="text-danger">${escapeHTML(data.reason)}</strong>
                    </div>` : '');
            }
            if (environmentReady) {
                setStep(1, 'done');
                setStep(2, 'active');
                setState('环境可用', 'success');
                const pidInput = byID('send-debug-pid');
                if (pidInput && !pidInput.value && data.wechat_pid) pidInput.placeholder = `自动发现 ${data.wechat_pid}`;
            } else {
                setStep(1, 'failed');
                setState('环境不可用', 'danger');
            }
        } catch (error) {
            if (box) box.innerHTML = `<div class="text-danger">环境检查失败：${escapeHTML(error.message)}</div>`;
            setStep(1, 'failed');
            setState('检查失败', 'danger');
        }
    };

    function fileAsDataURL(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(String(reader.result || ''));
            reader.onerror = () => reject(reader.error || new Error('读取图片失败'));
            reader.readAsDataURL(file);
        });
    }

    async function buildRequest(operation) {
        const targetType = value('send-debug-target-type') || 'private';
        const messageType = value('send-debug-message-type') || 'text';
        const request = {
            operation,
            target_type: targetType,
            message_type: messageType,
            user_id: targetType === 'private' ? value('send-debug-user-id') : '',
            group_id: targetType === 'group' ? value('send-debug-group-id') : '',
            content: value('send-debug-content'),
            at_user: targetType === 'group' ? value('send-debug-at-user') : '',
            at_name: targetType === 'group' ? value('send-debug-at-name') : '',
            sender: value('send-debug-sender'),
            pid: Number.parseInt(value('send-debug-pid'), 10) || 0,
            accept_risk: operation === 'send' && !!byID('send-debug-risk')?.checked,
            allow_elevation: !!byID('send-debug-elevation')?.checked,
            manual_release: true,
        };

        if (!request.user_id && !request.group_id) {
            throw new Error(targetType === 'group' ? '请填写 group_id' : '请填写 user_id');
        }
        if (targetType === 'group' && !request.group_id.toLowerCase().endsWith('@chatroom')) {
            throw new Error('群聊 group_id 必须以 @chatroom 结尾');
        }
        if (operation === 'send' && !request.accept_risk) {
            throw new Error('真实发送前必须勾选风险确认');
        }
        if (operation === 'send' && messageType === 'text' && !request.content) {
            throw new Error('请输入文本内容');
        }
        if (operation === 'send' && messageType === 'image') {
            const path = value('send-debug-image-path');
            const file = byID('send-debug-image')?.files?.[0];
            if (path && file) throw new Error('上传图片和服务端路径只能选择一个');
            if (!path && !file) throw new Error('请选择图片或填写服务端图片路径');
            if (file) {
                if (file.size <= 0 || file.size > 20 * 1024 * 1024) throw new Error('图片大小必须在 1 字节到 20 MiB 之间');
                request.image_data = await fileAsDataURL(file);
            } else {
                request.image_path = path;
            }
        }
        return request;
    }

    function setBusy(busy) {
        const probe = byID('send-debug-probe-btn');
        const send = byID('send-debug-send-btn');
        const messageType = byID('send-debug-message-type');
        if (probe) probe.disabled = busy;
        if (send) send.disabled = busy;
        if (messageType) messageType.disabled = busy;
        setHidden(byID('send-debug-cancel-btn'), !busy);
        if (!busy) {
            setHidden(byID('send-debug-release-btn'), true);
            if (send) send.textContent = '执行首次发送';
        }
    }

    async function submitNewJob(request, operation, switching = false) {
        activeMessageType = request.message_type || 'text';
        activeImageUsed = activeMessageType === 'image';
        activeOperation = operation;
        setBusy(true);
        setStep(2, 'done');
        setStep(operation === 'probe' ? 3 : 4, 'active');
        setState(switching ? `正在切换到${activeMessageType === 'image' ? '图片' : '文本'} Session` : (operation === 'probe' ? 'Hook 检查中' : '发送中'));
        byID('send-debug-progress-summary').textContent = switching
            ? '只读检查 Session 已安全结束，正在建立可同时发送图文的混合 Session。'
            : (operation === 'probe'
                ? '正在进行只读 attach-smoke，不会发送消息；检查完成后可选择文本或图片，系统会自动切换到发送 Session。'
                : '正在执行首次发送；完成后保持混合 Frida Session，文本和图片共用一次 attach。');
        byID('send-debug-progress').innerHTML = '<div class="analytics-empty">任务已提交，等待第一条进度...</div>';
        byID('send-debug-log').textContent = '任务已提交';

        const response = await fetch(`${apiBase}/jobs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request),
        });
        const data = await readJSON(response);
        if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
        activeJobID = data.id;
        byID('send-debug-job-id').textContent = `任务 ${activeJobID.slice(0, 8)}`;
        schedulePoll(0);
    }

    window.sendDebugStart = async function sendDebugStart(operation) {
        if (startInFlight || switchInFlight) return;
        if (activeJobID) {
            if (operation === 'send') await queuePersistentSend();
            return;
        }
        startInFlight = true;
        setBusy(true);
        try {
            if (!environmentReady) {
                await window.sendDebugCheckEnvironment();
                if (!environmentReady) {
                    setBusy(false);
                    return;
                }
                setBusy(true);
            }
            const request = await buildRequest(operation);
            await submitNewJob(request, operation);
        } catch (error) {
            setBusy(false);
            setState('启动失败', 'danger');
            setStep(operation === 'probe' ? 3 : 4, 'failed');
            byID('send-debug-progress-summary').textContent = `启动失败：${error.message}`;
        } finally {
            startInFlight = false;
        }
    };

    function schedulePoll(delay = 700) {
        if (pollTimer) window.clearTimeout(pollTimer);
        pollTimer = window.setTimeout(pollJob, delay);
    }

    async function readJob(id) {
        const response = await fetch(`${apiBase}/jobs/${encodeURIComponent(id)}`, { cache: 'no-store' });
        const job = await readJSON(response);
        if (!response.ok) throw new Error(job.error || `HTTP ${response.status}`);
        return job;
    }

    async function waitForJob(id, predicate, timeoutMs = 180000) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            const job = await readJob(id);
            if (predicate(job)) return job;
            await new Promise((resolve) => window.setTimeout(resolve, 250));
        }
        throw new Error('等待 Session 状态切换超时');
    }

    async function switchPersistentSession(request) {
        if (switchInFlight) throw new Error('消息类型切换正在进行');
        switchInFlight = true;
        const oldID = activeJobID;
        const nextType = request.message_type || 'text';
        setBusy(true);
        setState(`正在切换到${nextType === 'image' ? '图片' : '文本'} Session`, 'warning');
        byID('send-debug-progress-summary').textContent = '先等待旧队列完成，再执行 5 秒安全释放；图片 Session 会受控重启微信，然后自动建立新 Session。';
        try {
            let oldJob = await waitForJob(oldID, (job) =>
                !['queued', 'running', 'waiting_release'].includes(job.state)
                || (job.state === 'waiting_release' && (job.pending_commands || 0) === 0));
            if (['queued', 'running', 'waiting_release'].includes(oldJob.state)) {
                const response = await fetch(`${apiBase}/jobs/${encodeURIComponent(oldID)}/release`, { method: 'POST' });
                const data = await readJSON(response);
                if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
                oldJob = await waitForJob(oldID, (job) => !['queued', 'running', 'waiting_release'].includes(job.state));
            }
            if (!['succeeded', 'canceled', 'failed'].includes(oldJob.state)) {
                throw new Error(`旧 Session 结束状态异常：${oldJob.state || 'unknown'}`);
            }
            activeJobID = '';
            request.pid = 0;
            await submitNewJob(request, 'send', true);
        } finally {
            switchInFlight = false;
            if (!activeJobID) setBusy(false);
        }
    }

    function queuePersistentSend() {
        const queued = enqueueTail.then(() => queuePersistentSendNow());
        enqueueTail = queued.catch(() => {});
        return queued;
    }

    async function queuePersistentSendNow() {
        try {
            const request = await buildRequest('send');
            // Probe is read-only and must be replaced by a send session. Once a
            // send session exists, text and image commands share it directly;
            // changing the selector must never unload/re-attach Frida.
            if (activeOperation !== 'send') {
                await switchPersistentSession(request);
                return;
            }
            const jobID = activeJobID;
            const response = await fetch(`${apiBase}/jobs/${encodeURIComponent(jobID)}/send`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request),
            });
            const data = await readJSON(response);
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            if (jobID !== activeJobID) throw new Error('Session 已切换，本条命令未加入旧队列');
            setState('连续发送已排队');
            const imageMode = value('send-debug-message-type') === 'image';
            byID('send-debug-progress-summary').textContent = imageMode
                ? `图片命令 ${String(data.command_id || '').slice(0, 8)} 已排队；每张使用独立对象，可继续点击追加。`
                : `发送命令 ${String(data.command_id || '').slice(0, 8)} 已排队；可以继续点击追加消息。`;
            schedulePoll(100);
        } catch (error) {
            setState('连续发送入队失败', 'danger');
            byID('send-debug-progress-summary').textContent = `连续发送失败：${error.message}`;
        }
    }

    async function pollJob() {
        if (!activeJobID) return;
        const polledJobID = activeJobID;
        try {
            const response = await fetch(`${apiBase}/jobs/${encodeURIComponent(polledJobID)}`, { cache: 'no-store' });
            const job = await readJSON(response);
            if (activeJobID !== polledJobID) return;
            if (response.status === 404 || response.status === 410) {
                activeJobID = '';
                activeMessageType = '';
                activeImageUsed = false;
                activeOperation = '';
                setBusy(false);
                setState('原任务已不存在', 'warning');
                byID('send-debug-progress-summary').textContent = '服务已重启或任务记录已过期，可以重新建立 Session。';
                return;
            }
            if (!response.ok) throw new Error(job.error || `HTTP ${response.status}`);
            renderJob(job);
            if (['queued', 'running', 'waiting_release'].includes(job.state)) {
                schedulePoll();
                return;
            }
            if (!switchInFlight) {
                activeJobID = '';
                setBusy(false);
            }
        } catch (error) {
            byID('send-debug-progress-summary').textContent = `读取任务状态失败：${error.message}`;
            schedulePoll(1500);
        }
    }

    async function restoreActiveJob() {
        try {
            const response = await fetch(`${apiBase}/jobs/active`, { cache: 'no-store' });
            const job = await readJSON(response);
            if (!response.ok || !job.id || !['queued', 'running', 'waiting_release'].includes(job.state)) return;
            activeJobID = job.id;
            activeMessageType = job.request?.message_type || 'text';
            activeOperation = job.request?.operation || 'send';
            activeImageUsed = !!job.image_used;
            const messageType = byID('send-debug-message-type');
            if (messageType) messageType.value = activeMessageType;
            const targetType = byID('send-debug-target-type');
            if (targetType) targetType.value = job.request?.target_type || 'private';
            const userID = byID('send-debug-user-id');
            if (userID) userID.value = job.request?.user_id || '';
            const groupID = byID('send-debug-group-id');
            if (groupID) groupID.value = job.request?.group_id || '';
            const sender = byID('send-debug-sender');
            if (sender) sender.value = job.request?.sender || '';
            const pid = byID('send-debug-pid');
            if (pid) pid.value = job.request?.pid || '';
            window.sendDebugSyncForm();
            setBusy(true);
            byID('send-debug-job-id').textContent = `任务 ${activeJobID.slice(0, 8)}`;
            renderJob(job);
            schedulePoll();
        } catch (_) {
            // Environment feedback remains usable even if active-job recovery
            // is temporarily unavailable.
        }
    }

    function renderJob(job) {
        const progress = Array.isArray(job.progress) ? job.progress : [];
        const operation = job.request?.operation || 'send';
        const isImage = job.request?.message_type === 'image';
        activeImageUsed = !!job.image_used;
        const controlledMixedRelease = operation === 'send' && activeImageUsed;
        activeMessageType = isImage ? 'image' : 'text';
        activeOperation = operation;
        const isDone = !['queued', 'running', 'waiting_release'].includes(job.state);
        const succeeded = job.state === 'succeeded';

        if (job.state === 'queued') setState('排队中');
        if (job.state === 'running') setState(job.release_requested
            ? (controlledMixedRelease ? '正在安全结束混合 Session' : '正在释放 Frida')
            : (job.session_ready ? `连续发送中 · ${job.pending_commands || 0} 待处理` : (operation === 'probe' ? 'Hook 检查中' : '首次发送中')));
        if (job.state === 'waiting_release') setState('可继续发送 / 可手动释放', 'warning');
        if (succeeded) setState(operation === 'probe' ? 'Hook 检查通过' : (activeImageUsed ? '图文 Session 完成，微信已安全重启' : '发送完成且已释放'), 'success');
        if (job.state === 'failed') setState('任务失败', 'danger');
        if (job.state === 'canceled') setState('已停止并清理', 'warning');

        const releaseButton = byID('send-debug-release-btn');
        const sendButton = byID('send-debug-send-btn');
        const messageType = byID('send-debug-message-type');
        if (messageType) messageType.disabled = !!job.release_requested || switchInFlight;
        if (releaseButton) releaseButton.textContent = controlledMixedRelease ? '结束混合 Session（重启微信）' : '释放 Frida';
        if (!isDone && sendButton) {
            sendButton.disabled = !job.session_ready || job.release_requested;
            const selectedType = value('send-debug-message-type') || activeMessageType;
            if (!job.session_ready) sendButton.textContent = '等待 Session 就绪';
            else if (operation === 'probe') sendButton.textContent = `结束检查并发送${selectedType === 'image' ? '图片' : '文本'}`;
            else sendButton.textContent = `发送${selectedType === 'image' ? '图片' : '文本'}`;
        }
        if (job.state === 'waiting_release') {
            if (operation === 'probe') setStep(3, 'done');
            setStep(4, 'active');
            setHidden(releaseButton, false);
            if (releaseButton) releaseButton.disabled = false;
        } else {
            setHidden(releaseButton, true);
        }
        if (isDone) {
            if (operation === 'probe' && succeeded) setStep(3, 'done');
            setStep(4, succeeded ? 'done' : 'failed');
        }
        const summary = byID('send-debug-progress-summary');
        if (summary) {
            if (job.error) summary.textContent = job.error;
            else if (job.state === 'waiting_release') summary.textContent = operation === 'probe'
                ? 'Hook 检查通过。可选择文本或图片并点击发送；系统会先安全释放检查 Session，再自动建立发送 Session。'
                : `混合 session 已就绪；已完成 ${job.completed_sends || 0} 次发送。可直接交替发送文本和图片，不会因切换类型清理 Session；最终结束等待 5 秒。`;
            else if (job.state === 'running' && job.release_requested) summary.textContent = controlledMixedRelease
                ? '正在补足图片 generation 安全窗口；随后受控重启微信、清理 Frida helper 并检查新 PID。'
                : '正在补足最后一条消息的安全窗口，然后执行 force_cleanup、unload 和 detach。';
            else if (job.session_ready && job.pending_commands > 0) summary.textContent = `连续发送队列处理中：${job.pending_commands} 条待完成，已完成 ${job.completed_sends || 0} 条；仍可继续点击追加。`;
            else if (succeeded) summary.textContent = activeImageUsed
                ? '混合图文任务完成；旧微信进程已受控退出，新微信进程健康，Frida helper 无残留。'
                : (job.result?.elevated
                    ? '任务完成；手动释放成功，临时管理员授权子进程已经退出。'
                    : '任务完成；手动释放成功，Frida hooks 和 session 已释放。');
            else summary.textContent = progress.at(-1)?.message || '任务运行中...';
        }

        const progressBox = byID('send-debug-progress');
        if (progressBox) {
            progressBox.innerHTML = progress.length ? progress.slice(-160).map((item) => {
                const d = item.time ? new Date(item.time) : new Date();
                const time = Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString();
                const stage = stageLabel(item.stage, item.step, item.total, item.command_id);
                return `<div class="send-debug-progress-row ${escapeHTML(item.level || '')}">
                    <span class="send-debug-progress-time">${escapeHTML(time)}</span>
                    <span class="send-debug-progress-stage">${escapeHTML(stage)}</span>
                    <span class="send-debug-progress-message">${escapeHTML(item.message || '')}</span>
                </div>`;
            }).join('') : '<div class="analytics-empty">任务已启动，等待进度...</div>';
            progressBox.scrollTop = progressBox.scrollHeight;
        }
        const log = byID('send-debug-log');
        if (log) {
            log.textContent = progress.map((item) => {
                const step = item.step ? `[${item.step}/${item.total}] ` : '';
                return `${step}${item.stage || 'native'}: ${item.message || ''}`;
            }).join('\n') || '暂无日志';
        }
    }

    function stageLabel(stage, step, total, commandID = '') {
        const labels = {
            environment: '环境', launch: '启动', native: 'Native', event: '事件',
            cleanup: '资源释放', health: '健康检查', drain: '延迟回调', elevation: '管理员授权',
            manual_release: '手动释放',
            command: '连续发送',
        };
        if (commandID) return `${labels[stage] || stage} ${String(commandID).slice(0, 8)}`;
        if (step) return `${step}/${total || '?'} ${labels[stage] || stage}`;
        return labels[stage] || stage || '进度';
    }

    window.sendDebugCancel = async function sendDebugCancel() {
        if (!activeJobID) return;
        const id = activeJobID;
        try {
            const response = await fetch(`${apiBase}/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
            const data = await readJSON(response);
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            setState('正在停止');
            byID('send-debug-progress-summary').textContent = activeOperation === 'send' && activeImageUsed
                ? '已请求停止混合 session；由于发送过图片，将受控重启微信并清理 Frida helper。'
                : '已请求停止；等待脚本执行 force_cleanup、unload 和 detach。';
            schedulePoll(200);
        } catch (error) {
            byID('send-debug-progress-summary').textContent = `停止失败：${error.message}`;
        }
    };

    window.sendDebugRelease = async function sendDebugRelease() {
        if (!activeJobID) return;
        const id = activeJobID;
        const button = byID('send-debug-release-btn');
        if (button) button.disabled = true;
        try {
            const response = await fetch(`${apiBase}/jobs/${encodeURIComponent(id)}/release`, { method: 'POST' });
            const data = await readJSON(response);
            if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
            setHidden(button, true);
            const controlledImageRelease = activeOperation === 'send' && activeImageUsed;
            setState(controlledImageRelease ? '正在安全结束混合 Session' : '正在释放 Frida');
            byID('send-debug-progress-summary').textContent = controlledImageRelease
                ? '结束指令已提交；将补足 generation 安全窗口，随后受控重启微信、清理 helper 并检查新 PID。'
                : '释放指令已提交；将补足最终 drain 安全窗口后执行 cleanup、unload 和 detach。';
            schedulePoll(200);
        } catch (error) {
            if (button) button.disabled = false;
            byID('send-debug-progress-summary').textContent = `释放失败：${error.message}`;
        }
    };

    let initialized = false;
    let initializationPromise = null;

    window.sendDebugInitialize = function sendDebugInitialize() {
        if (initialized) return Promise.resolve();
        if (initializationPromise) return initializationPromise;
        initializationPromise = (async () => {
            window.sendDebugSyncForm();
            await window.sendDebugCheckEnvironment();
            await restoreActiveJob();
            initialized = true;
        })().finally(() => {
            initializationPromise = null;
        });
        return initializationPromise;
    };

    document.addEventListener('DOMContentLoaded', () => {
        // Keep form state correct without probing Frida or polling jobs until
        // the user actually opens the send-debug tab.
        window.sendDebugSyncForm();
    });
})();
