class IPInfoTool {
    constructor() {
        this.currentIP = null;
        this.currentDomain = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadIPInfo();
    }

    bindEvents() {
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.loadIPInfo();
        });

        document.getElementById('search-btn').addEventListener('click', () => {
            this.searchIP();
        });

        document.getElementById('ip-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.searchIP();
            }
        });

        document.getElementById('domain-search-btn').addEventListener('click', () => {
            this.searchDomain();
        });

        document.getElementById('domain-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.searchDomain();
            }
        });


        document.getElementById('propagation-check-btn').addEventListener('click', () => {
            this.checkDNSPropagation();
        });

        document.getElementById('propagation-domain-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.checkDNSPropagation();
            }
        });

        document.getElementById('port-scan-btn').addEventListener('click', () => {
            this.startPortScan();
        });

        document.getElementById('port-scan-target').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.startPortScan();
            }
        });

        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const ports = e.target.getAttribute('data-ports');
                document.getElementById('custom-ports').value = ports;
            });
        });

    }

    async searchIP() {
        const inputIP = document.getElementById('ip-input').value.trim();
        
        if (inputIP === '') {
            this.loadIPInfo();
        } else {
            if (!this.isValidIP(inputIP)) {
                alert('有効なIPアドレスを入力してください');
                return;
            }
            await this.loadIPInfoForSpecificIP(inputIP);
        }
    }

    async loadIPInfoForSpecificIP(ip) {
        try {
            this.setStatus('ip-address', ip);
            this.setLoadingStatus();

            this.currentIP = ip;

            const ipInfo = await this.fetchSpecificIPInfo(ip);
            this.displayIPInfo(ipInfo);

            await this.loadReverseDNS(ip);
        } catch (error) {
            console.error('IP情報の取得に失敗:', error);
            this.setErrorStatus();
        }
    }

    async fetchSpecificIPInfo(ip) {
        const response = await fetch(`https://ipinfo.io/${ip}/json`);
        if (!response.ok) {
            throw new Error('IP情報の取得に失敗しました');
        }
        return await response.json();
    }

    isValidIP(ip) {
        return this.isIPv4(ip) || this.isIPv6(ip);
    }

    isIPv6(ip) {
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        const ipv6CompressedRegex = /^([0-9a-fA-F]{0,4}:){0,7}:([0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4}$/;
        return ipv6Regex.test(ip) || ipv6CompressedRegex.test(ip);
    }


    async loadIPInfo() {
        try {
            this.setLoadingStatus();

            const ipInfo = await this.fetchIPInfo();
            this.currentIP = ipInfo.ip;
            
            this.displayIPInfo(ipInfo);
            await this.loadReverseDNS(ipInfo.ip);
        } catch (error) {
            console.error('IP情報の取得に失敗:', error);
            this.setErrorStatus();
        }
    }

    async fetchIPInfo() {
        const response = await fetch('https://ipinfo.io/json');
        if (!response.ok) {
            throw new Error('IP情報の取得に失敗しました');
        }
        return await response.json();
    }

    async loadReverseDNS(ip) {
        try {
            const reverseDNS = await this.fetchReverseDNS(ip);
            this.currentDomain = reverseDNS;
            this.setStatus('reverse-dns', reverseDNS || 'なし');
        } catch (error) {
            console.error('逆引きDNSの取得に失敗:', error);
            this.setStatus('reverse-dns', 'エラー', 'error');
            this.currentDomain = null;
        }
    }

    async fetchReverseDNS(ip) {
        try {
            const response = await fetch(`https://1.1.1.1/dns-query?name=${this.getReverseDNSName(ip)}&type=PTR`, {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });
            
            if (!response.ok) {
                throw new Error('DNS query failed');
            }
            
            const data = await response.json();
            
            if (data.Answer && data.Answer.length > 0) {
                return data.Answer[0].data.replace(/\.$/, '');
            }
            
            return null;
        } catch (error) {
            console.error('逆引きDNS取得エラー:', error);
            return null;
        }
    }

    getReverseDNSName(ip) {
        if (this.isIPv4(ip)) {
            return ip.split('.').reverse().join('.') + '.in-addr.arpa';
        } else {
            const expanded = this.expandIPv6(ip);
            return expanded.replace(/:/g, '').split('').reverse().join('.') + '.ip6.arpa';
        }
    }





    isIPv4(ip) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        return ipv4Regex.test(ip);
    }

    expandIPv6(ip) {
        const parts = ip.split(':');
        const expanded = [];
        
        for (let i = 0; i < parts.length; i++) {
            if (parts[i] === '') {
                const zerosToAdd = 8 - parts.filter(p => p !== '').length;
                for (let j = 0; j <= zerosToAdd; j++) {
                    expanded.push('0000');
                }
            } else {
                expanded.push(parts[i].padStart(4, '0'));
            }
        }
        
        return expanded.slice(0, 8).join(':');
    }

    setStatus(elementId, text, className = '') {
        const element = document.getElementById(elementId);
        element.textContent = text;
        element.className = className;
    }

    setLoadingStatus() {
        this.setStatus('ip-address', '取得中...', 'loading');
        this.setStatus('reverse-dns', '取得中...', 'loading');
        this.setStatus('isp', '-');
        this.setStatus('country', '-');
        this.setStatus('region', '-');
        this.setStatus('ipinfo-url', '-');
    }

    setErrorStatus() {
        this.setStatus('ip-address', 'エラー', 'error');
        this.setStatus('reverse-dns', 'エラー', 'error');
        this.setStatus('isp', 'エラー', 'error');
        this.setStatus('country', 'エラー', 'error');
        this.setStatus('region', 'エラー', 'error');
        this.setStatus('ipinfo-url', 'エラー', 'error');
    }

    displayIPInfo(ipInfo) {
        this.setStatus('ip-address', ipInfo.ip || 'N/A');
        this.setStatus('isp', ipInfo.org || 'N/A');
        this.setStatus('country', ipInfo.country || 'N/A');
        this.setStatus('region', ipInfo.region || 'N/A');
        
        const ipinfoUrl = `https://ipinfo.io/${ipInfo.ip || this.currentIP}`;
        this.setStatus('ipinfo-url', ipinfoUrl);
    }

    async searchDomain() {
        const inputDomain = document.getElementById('domain-input').value.trim();
        
        if (inputDomain === '') {
            alert('ドメイン名を入力してください');
            return;
        }

        if (!this.isValidDomain(inputDomain)) {
            alert('有効なドメイン名を入力してください');
            return;
        }

        await this.loadDomainInfo(inputDomain);
    }

    async loadDomainInfo(domain) {
        try {
            this.setDomainLoadingStatus();
            this.setStatus('domain-name', domain);

            const [aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords] = await Promise.allSettled([
                this.fetchDNSRecords(domain, 'A'),
                this.fetchDNSRecords(domain, 'AAAA'),
                this.fetchDNSRecords(domain, 'MX'),
                this.fetchDNSRecords(domain, 'NS'),
                this.fetchDNSRecords(domain, 'TXT')
            ]);

            this.setStatus('domain-ip', this.formatDNSResults(aRecords));
            this.setStatus('domain-ipv6', this.formatDNSResults(aaaaRecords));
            this.setStatus('domain-mx', this.formatDNSResults(mxRecords));
            this.setStatus('domain-ns', this.formatDNSResults(nsRecords));
            this.setStatus('domain-txt', this.formatDNSResults(txtRecords));
        } catch (error) {
            console.error('ドメイン情報の取得に失敗:', error);
            this.setDomainErrorStatus();
        }
    }

    async fetchDNSRecords(domain, type) {
        const response = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=${type}`, {
            headers: {
                'Accept': 'application/dns-json'
            }
        });

        if (!response.ok) {
            throw new Error('DNS query failed');
        }

        const data = await response.json();
        return data.Answer || [];
    }

    formatDNSResults(promiseResult) {
        if (promiseResult.status === 'rejected') {
            return 'エラー';
        }

        const records = promiseResult.value;
        if (records.length === 0) {
            return 'なし';
        }

        return records.map(record => record.data).join('\n');
    }

    setDomainLoadingStatus() {
        this.setStatus('domain-ip', '取得中...', 'loading');
        this.setStatus('domain-ipv6', '取得中...', 'loading');
        this.setStatus('domain-mx', '取得中...', 'loading');
        this.setStatus('domain-ns', '取得中...', 'loading');
        this.setStatus('domain-txt', '取得中...', 'loading');
    }

    setDomainErrorStatus() {
        this.setStatus('domain-ip', 'エラー', 'error');
        this.setStatus('domain-ipv6', 'エラー', 'error');
        this.setStatus('domain-mx', 'エラー', 'error');
        this.setStatus('domain-ns', 'エラー', 'error');
        this.setStatus('domain-txt', 'エラー', 'error');
    }

    isValidDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return domainRegex.test(domain);
    }

    async checkDNSPropagation() {
        const domain = document.getElementById('propagation-domain-input').value.trim();
        const recordType = document.getElementById('record-type-select').value;

        if (domain === '') {
            alert('ドメイン名を入力してください');
            return;
        }

        if (!this.isValidDomain(domain)) {
            alert('有効なドメイン名を入力してください');
            return;
        }

        this.setStatus('propagation-status', `${domain}の${recordType}レコードをチェック中...`, 'loading');
        document.getElementById('propagation-results-grid').innerHTML = '';

        const dnsServers = [
            { name: '🇺🇸 US Cloudflare', server: '1.1.1.1', country: 'US' },
            { name: '🇯🇵 JP IIJ', server: '202.232.2.16', country: 'JP' },
            { name: '🇰🇷 KR KT', server: '168.126.63.1', country: 'KR' },
            { name: '🇸🇬 SG OpenDNS', server: '208.67.222.222', country: 'SG' },
            { name: '🇦🇺 AU Telstra', server: '139.130.4.5', country: 'AU' },
            { name: '🇫🇷 FR AdGuard', server: '94.140.14.14', country: 'FR' },
            { name: '🇩🇪 DE DNS.Watch', server: '84.200.69.80', country: 'DE' },
            { name: '🇬🇧 GB CleanBrowsing', server: '185.228.168.9', country: 'GB' },
            { name: '🇨🇦 CA Shaw', server: '64.59.144.16', country: 'CA' }
        ];

        try {
            const results = await Promise.allSettled(
                dnsServers.map(server => this.queryDNSServer(domain, recordType, server))
            );

            this.displayPropagationResults(results, domain, recordType);
        } catch (error) {
            console.error('DNS伝播チェックに失敗:', error);
            this.setStatus('propagation-status', 'DNS伝播チェックに失敗しました', 'error');
        }
    }

    async queryDNSServer(domain, recordType, serverInfo) {
        // DNS over HTTPSを使用してクエリ
        const response = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=${recordType}`, {
            headers: {
                'Accept': 'application/dns-json'
            }
        });

        if (!response.ok) {
            throw new Error(`DNS query failed for ${serverInfo.name}`);
        }

        const data = await response.json();
        return {
            server: serverInfo,
            records: data.Answer || [],
            status: data.Status || 0
        };
    }

    displayPropagationResults(results, domain, recordType) {
        const gridElement = document.getElementById('propagation-results-grid');
        const successfulResults = results.filter(result => result.status === 'fulfilled');
        const totalServers = results.length;
        const propagatedServers = successfulResults.filter(result => 
            result.value.records.length > 0
        ).length;

        // ステータス更新
        const propagationRate = ((propagatedServers / totalServers) * 100).toFixed(1);
        this.setStatus('propagation-status', 
            `${domain}の${recordType}レコード: ${propagatedServers}/${totalServers}のサーバーで解決済み (${propagationRate}%)`
        );

        // 結果グリッド表示
        gridElement.innerHTML = '';
        results.forEach((result, index) => {
            const serverDiv = document.createElement('div');
            serverDiv.className = 'propagation-result';

            if (result.status === 'fulfilled') {
                const data = result.value;
                const hasRecords = data.records.length > 0;
                
                serverDiv.innerHTML = `
                    <div class="server-name">${data.server.name}</div>
                    <div class="server-ip">${data.server.server}</div>
                    <div class="result-status ${hasRecords ? 'success' : 'no-records'}">
                        ${hasRecords ? '✓ 解決済み' : '✗ レコードなし'}
                    </div>
                    <div class="result-data">
                        ${hasRecords ? data.records.map(r => r.data).join('<br>') : '-'}
                    </div>
                `;
            } else {
                serverDiv.innerHTML = `
                    <div class="server-name">サーバー ${index + 1}</div>
                    <div class="server-ip">-</div>
                    <div class="result-status error">✗ エラー</div>
                    <div class="result-data">接続失敗</div>
                `;
            }

            gridElement.appendChild(serverDiv);
        });
    }

    async startPortScan() {
        const target = document.getElementById('port-scan-target').value.trim();
        const customPorts = document.getElementById('custom-ports').value.trim();

        if (!target) {
            alert('スキャン対象のIPアドレスまたはドメイン名を入力してください');
            return;
        }

        // プライベートIPアドレスのみ遮断
        if (this.isPrivateIP(target)) {
            alert('プライベートIPアドレスはスキャンできません。\nグローバルIPアドレスまたはドメイン名を使用してください。');
            return;
        }

        if (!customPorts) {
            alert('スキャンするポートを指定してください');
            return;
        }

        const ports = this.parsePorts(customPorts);
        if (ports.length === 0) {
            alert('有効なポート番号を入力してください');
            return;
        }

        if (ports.length > 5) {
            alert('セキュリティ配慮により、最大5ポートまでしかスキャンできません。');
            return;
        }

        this.displayPortScanStart(target, ports);
        await this.performPortScan(target, ports);
    }

    parsePorts(portsString) {
        const ports = [];
        const parts = portsString.split(',');

        for (const part of parts) {
            const trimmed = part.trim();
            
            if (trimmed.includes('-')) {
                const [start, end] = trimmed.split('-').map(p => parseInt(p.trim()));
                if (start && end && start <= end && start > 0 && end <= 65535) {
                    const rangeSize = end - start + 1;
                    if (rangeSize > 5) {
                        alert(`範囲指定は最大5ポートまでです。${start}-${end}は${rangeSize}ポートになります。`);
                        continue;
                    }
                    for (let i = start; i <= end; i++) {
                        ports.push(i);
                    }
                }
            } else {
                const port = parseInt(trimmed);
                if (port && port > 0 && port <= 65535) {
                    ports.push(port);
                }
            }
        }

        return [...new Set(ports)].sort((a, b) => a - b);
    }

    displayPortScanStart(target, ports) {
        document.getElementById('port-scan-status').textContent = `${target} の ${ports.length} ポートをスキャン中...`;
        document.getElementById('port-scan-progress').style.display = 'block';
        document.getElementById('progress-fill').style.width = '0%';
        document.getElementById('progress-text').textContent = `0 / ${ports.length} ポート完了`;
        document.getElementById('port-results-grid').innerHTML = '';
    }

    async performPortScan(target, ports) {
        const results = [];
        const batchSize = 10;
        let completed = 0;

        for (let i = 0; i < ports.length; i += batchSize) {
            const batch = ports.slice(i, i + batchSize);
            const batchPromises = batch.map(port => this.scanPort(target, port));
            
            try {
                const batchResults = await Promise.allSettled(batchPromises);
                
                for (let j = 0; j < batchResults.length; j++) {
                    const port = batch[j];
                    const result = batchResults[j];
                    
                    if (result.status === 'fulfilled') {
                        results.push({
                            port: port,
                            status: result.value.status,
                            service: this.getServiceName(port),
                            responseTime: result.value.responseTime
                        });
                    } else {
                        results.push({
                            port: port,
                            status: 'closed',
                            service: this.getServiceName(port),
                            responseTime: null
                        });
                    }
                    
                    completed++;
                    this.updateProgress(completed, ports.length);
                }
            } catch (error) {
                console.error('Port scan batch error:', error);
            }

            await new Promise(resolve => setTimeout(resolve, 100));
        }

        this.displayPortScanResults(target, results);
    }

    async scanPort(target, port) {
        const startTime = Date.now();
        
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('timeout'));
            }, 5000);

            const protocol = location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(`${protocol}${target}:${port}`);
            
            ws.onopen = () => {
                clearTimeout(timeout);
                ws.close();
                resolve({
                    status: 'open',
                    responseTime: Date.now() - startTime
                });
            };

            ws.onerror = () => {
                clearTimeout(timeout);
                
                fetch(`http://${target}:${port}`, {
                    method: 'HEAD',
                    mode: 'no-cors',
                    signal: AbortSignal.timeout(3000)
                })
                .then(() => {
                    resolve({
                        status: 'open',
                        responseTime: Date.now() - startTime
                    });
                })
                .catch(() => {
                    reject(new Error('closed'));
                });
            };
        });
    }

    updateProgress(completed, total) {
        const percentage = (completed / total) * 100;
        document.getElementById('progress-fill').style.width = `${percentage}%`;
        document.getElementById('progress-text').textContent = `${completed} / ${total} ポート完了`;
    }

    getServiceName(port) {
        const services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3000: 'Dev Server',
            3001: 'Dev Server',
            8080: 'HTTP Alt',
            8443: 'HTTPS Alt',
            9000: 'Dev Server'
        };
        return services[port] || 'Unknown';
    }

    displayPortScanResults(target, results) {
        document.getElementById('port-scan-progress').style.display = 'none';
        
        const openPorts = results.filter(r => r.status === 'open').length;
        const totalPorts = results.length;
        
        document.getElementById('port-scan-status').textContent = 
            `${target} のスキャン完了: ${openPorts}/${totalPorts} ポートが開放されています`;

        const gridElement = document.getElementById('port-results-grid');
        gridElement.innerHTML = '';

        results.forEach(result => {
            const portDiv = document.createElement('div');
            portDiv.className = `port-result ${result.status}`;
            
            portDiv.innerHTML = `
                <div class="port-number">${result.port}</div>
                <div class="port-service">${result.service}</div>
                <div class="port-status">${result.status === 'open' ? '開放' : '閉鎖'}</div>
                <div class="port-response">${result.responseTime ? `${result.responseTime}ms` : '-'}</div>
            `;
            
            gridElement.appendChild(portDiv);
        });
    }

    // セキュリティ関連メソッド
    isPrivateIP(ip) {
        // IPv4プライベートアドレス範囲とlocalhostをチェック
        const privateRanges = [
            /^127\./,                   // 127.0.0.0/8 (localhost)
            /^10\./,                    // 10.0.0.0/8
            /^172\.(1[6-9]|2[0-9]|3[01])\./,  // 172.16.0.0/12
            /^192\.168\./               // 192.168.0.0/16
        ];
        
        // localhostの文字列チェック
        if (ip.toLowerCase() === 'localhost' || ip === '::1') {
            return true;
        }
        
        return privateRanges.some(range => range.test(ip));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new IPInfoTool();
});