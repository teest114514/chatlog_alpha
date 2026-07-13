(() => {
    const storageKey = 'chatlog.console.activeTab';
    const statusRefreshMs = 15000;

    if ('scrollRestoration' in history) {
        history.scrollRestoration = 'manual';
    }

    function tabButtons() {
        return Array.from(document.querySelectorAll('.tab-btn'));
    }

    function tabID(button) {
        const match = String(button.getAttribute('onclick') || '').match(/switchTab\('([^']+)'\)/);
        return match ? match[1] : '';
    }

    function availableTab(tab) {
        return Boolean(tab && document.getElementById(tab) && tabButtons().some((button) => tabID(button) === tab));
    }

    function rememberTab(tab) {
        if (!availableTab(tab)) return;
        try {
            localStorage.setItem(storageKey, tab);
        } catch (_) {
            // Storage may be disabled; navigation still works normally.
        }
        syncTabAccessibility(tab);
    }

    function syncTabAccessibility(activeTab) {
        tabButtons().forEach((button) => {
            const selected = tabID(button) === activeTab;
            button.setAttribute('role', 'tab');
            button.setAttribute('aria-selected', String(selected));
            button.setAttribute('tabindex', selected ? '0' : '-1');
        });
    }

    async function refreshServiceStatus() {
        const badge = document.getElementById('service-status');
        if (!badge) return;
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 3500);
        try {
            const response = await fetch('/health', { cache: 'no-store', signal: controller.signal });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            badge.classList.remove('offline');
            badge.classList.add('online');
            badge.textContent = '服务正常';
            badge.title = `最近检查：${new Date().toLocaleTimeString()}`;
        } catch (_) {
            badge.classList.remove('online');
            badge.classList.add('offline');
            badge.textContent = '连接中断';
            badge.title = '无法连接本地 Chatlog 服务';
        } finally {
            window.clearTimeout(timeout);
        }
    }

    function openGlobalSearch() {
        if (typeof window.switchTab !== 'function') return;
        window.switchTab('global-search');
        rememberTab('global-search');
        window.setTimeout(() => document.getElementById('global-search-keyword')?.focus(), 0);
    }

    document.addEventListener('DOMContentLoaded', () => {
        const requestedHashTab = decodeURIComponent(location.hash.replace(/^#/, ''));
        if (location.hash) {
            history.replaceState(null, '', `${location.pathname}${location.search}`);
        }
        const tabs = document.querySelector('.tabs');
        tabs?.setAttribute('role', 'tablist');
        tabs?.setAttribute('aria-label', '控制台功能导航');

        tabButtons().forEach((button) => {
            button.addEventListener('click', () => {
                rememberTab(tabID(button));
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
            button.addEventListener('keydown', (event) => {
                if (event.key !== 'ArrowDown' && event.key !== 'ArrowRight' && event.key !== 'ArrowUp' && event.key !== 'ArrowLeft') return;
                event.preventDefault();
                const buttons = tabButtons();
                const direction = event.key === 'ArrowDown' || event.key === 'ArrowRight' ? 1 : -1;
                const next = buttons[(buttons.indexOf(button) + direction + buttons.length) % buttons.length];
                next.focus();
                next.click();
            });
        });

        let saved = requestedHashTab;
        if (!availableTab(saved)) {
            try {
                saved = localStorage.getItem(storageKey) || '';
            } catch (_) {
                saved = '';
            }
        }
        if (availableTab(saved) && typeof window.switchTab === 'function') {
            window.switchTab(saved);
        } else {
            saved = tabID(document.querySelector('.tab-btn.active')) || 'dashboard';
        }
        rememberTab(saved);
        window.scrollTo(0, 0);

        document.addEventListener('keydown', (event) => {
            if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
                event.preventDefault();
                openGlobalSearch();
            }
        });

        refreshServiceStatus();
        window.setInterval(refreshServiceStatus, statusRefreshMs);
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) refreshServiceStatus();
        });
    });

    window.addEventListener('load', () => window.scrollTo(0, 0), { once: true });
})();
