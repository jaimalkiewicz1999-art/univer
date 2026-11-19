/**
 * Copyright 2023-present DreamNum Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { ILogService, LocaleService } from '@univerjs/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserClipboardService } from '../clipboard-interface.service';
import { supportClipboardAPI } from '../clipboard-utils';

vi.mock('../clipboard-utils', () => ({
    supportClipboardAPI: vi.fn(),
}));

class MockClipboardItem {
    constructor(public readonly items: Record<string, Blob>) {}
}

function createService() {
    const localeService = {
        t: vi.fn((key: string) => key),
    } as unknown as LocaleService;
    const logService = {
        error: vi.fn(),
    } as unknown as ILogService;
    const notificationService = {
        show: vi.fn(),
    };

    const service = new BrowserClipboardService(localeService, logService, notificationService as any);

    return { service, localeService, logService, notificationService };
}

describe('BrowserClipboardService', () => {
    beforeEach(() => {
        vi.mocked(supportClipboardAPI).mockReturnValue(true);
        vi.stubGlobal('ClipboardItem', MockClipboardItem);
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: {
                write: vi.fn().mockResolvedValue(undefined),
                writeText: vi.fn().mockResolvedValue(undefined),
                read: vi.fn().mockResolvedValue([]),
                readText: vi.fn().mockResolvedValue('clipboard-text'),
            },
        });
        (document as any).execCommand = vi.fn(() => true);
    });

    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
        document.body.replaceChildren();
        window.getSelection()?.removeAllRanges();
    });

    it('should expose clipboard support from utility', () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(true);
        const { service } = createService();
        expect(service.supportClipboard).toBe(true);
    });

    it('should write plain text and html with modern clipboard api', async () => {
        const { service } = createService();

        await service.write('plain', '<b>plain</b>');

        expect(navigator.clipboard.write).toHaveBeenCalledTimes(1);
    });

    it('should write text with modern clipboard api', async () => {
        const { service } = createService();

        await service.writeText('hello');
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('hello');
    });

    it('should fallback to legacy copy when clipboard api is unsupported', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();

        const input = document.createElement('input');
        document.body.appendChild(input);
        input.focus();

        await service.writeText('legacy-text');
        await service.write('legacy', '<i>legacy</i>');

        expect(document.execCommand).toHaveBeenCalledWith('copy');
    });

    it('should fallback to legacy copy when ClipboardItem is unavailable', async () => {
        vi.stubGlobal('ClipboardItem', undefined);
        const { service } = createService();

        await service.write('legacy', '<i>legacy</i>');

        expect(document.execCommand).toHaveBeenCalledWith('copy');
        expect(navigator.clipboard.write).not.toHaveBeenCalled();
    });

    it('should write raw sanitized html during legacy copy event', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        const clipboardData = {
            setData: vi.fn(),
        };

        vi.mocked(document.execCommand).mockImplementation(() => {
            const event = new Event('copy', { cancelable: true }) as ClipboardEvent;
            Object.defineProperty(event, 'clipboardData', {
                value: clipboardData,
            });
            document.dispatchEvent(event);
            return true;
        });

        await service.write('plain', '<div onclick="alert(1)" style="color:red">rich</div>');

        expect(clipboardData.setData).toHaveBeenCalledWith('text/plain', 'plain');
        expect(clipboardData.setData).toHaveBeenCalledWith('text/html', '<div style="color: red">rich</div>');
        expect(document.body.lastElementChild?.textContent).not.toBe('rich');
    });

    it('should preserve Univer Excel metadata while sanitizing legacy html', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        const clipboardData = {
            setData: vi.fn(),
        };

        vi.mocked(document.execCommand).mockImplementation(() => {
            const event = new Event('copy', { cancelable: true }) as ClipboardEvent;
            Object.defineProperty(event, 'clipboardData', {
                value: clipboardData,
            });
            document.dispatchEvent(event);
            return true;
        });

        await service.write(
            'merged',
            '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta name="ProgId" content="Excel.Sheet"><meta name="Generator" content="Univer"><script>alert(1)</script></head><body><!--StartFragment--><table data-copy-id="copy-id"><tbody><tr><td rowspan="3" onclick="alert(1)">merged</td></tr></tbody></table><!--EndFragment--></body></html>'
        );

        const copiedHtml = clipboardData.setData.mock.calls.find(([type]) => type === 'text/html')?.[1];

        expect(copiedHtml).toContain('xmlns:x="urn:schemas-microsoft-com:office:excel"');
        expect(copiedHtml).toContain('<meta name="ProgId" content="Excel.Sheet">');
        expect(copiedHtml).toContain('<!--StartFragment--><table data-copy-id="copy-id">');
        expect(copiedHtml).toContain('<td rowspan="3">merged</td>');
        expect(copiedHtml).toContain('</table><!--EndFragment-->');
        expect(copiedHtml).not.toContain('<script');
        expect(copiedHtml).not.toContain('onclick');
    });

    it('should sanitize html before legacy copy', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        let copiedHtml = '';

        vi.mocked(document.execCommand).mockImplementation(() => {
            copiedHtml = document.body.lastElementChild?.innerHTML ?? '';
            return true;
        });

        await service.write(
            'legacy',
            '<div data-copy-id="copy-id" onclick="alert(1)"><a href="javascript:alert(1)">unsafe</a><img src="data:image/png;base64,ZmFrZQ==" onerror="alert(1)" /><span style="color: red; background-image: url(javascript:alert(1))">safe</span><script>alert(1)</script></div>'
        );

        const copiedDocument = new DOMParser().parseFromString(copiedHtml, 'text/html');
        const wrapper = copiedDocument.body.firstElementChild as HTMLDivElement | null;
        const link = copiedDocument.querySelector('a');
        const image = copiedDocument.querySelector('img');
        const span = copiedDocument.querySelector('span');

        expect(wrapper?.getAttribute('data-copy-id')).toBe('copy-id');
        expect(wrapper?.hasAttribute('onclick')).toBe(false);
        expect(copiedDocument.querySelector('script')).toBeNull();
        expect(link?.hasAttribute('href')).toBe(false);
        expect(image?.getAttribute('src')).toBe('data:image/png;base64,ZmFrZQ==');
        expect(image?.hasAttribute('onerror')).toBe(false);
        expect(span?.getAttribute('style')).toContain('color: red');
        expect(span?.getAttribute('style')).not.toContain('url(');
    });

    it('should attach sanitized nodes without parsing HTML strings in the live fallback container', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')!;
        let liveHtmlWrites = 0;
        let copiedContainer: Element | undefined;

        vi.spyOn(Element.prototype, 'innerHTML', 'set').mockImplementation(function (this: Element, value: string) {
            if (this.isConnected) {
                liveHtmlWrites++;
            }
            descriptor.set!.call(this, value);
        });
        vi.mocked(document.execCommand).mockImplementation(() => {
            const container = document.body.lastElementChild;
            if (container instanceof HTMLDivElement) {
                copiedContainer = container.cloneNode(true) as Element;
            }
            return true;
        });

        await service.write('rich', '<table data-copy-id="safe"><tr><td rowspan="2" onclick="alert(1)">rich</td></tr></table>');

        expect(liveHtmlWrites).toBe(0);
        expect(copiedContainer?.querySelector('table')?.getAttribute('data-copy-id')).toBe('safe');
        expect(copiedContainer?.querySelector('td')?.getAttribute('rowspan')).toBe('2');
        expect(copiedContainer?.querySelector('[onclick]')).toBeNull();
        expect(copiedContainer?.textContent).toBe('rich');
        expect(document.body.childElementCount).toBe(0);
    });

    it.each([
        ['scripts and handlers', '<div onclick="alert(1)">rich<img src="/image" onerror="alert(1)"><script>alert(1)</script></div>'],
        ['encoded protocols', '<a href="java&#x73;cript:alert(1)">rich</a><a href="java&#10;script:alert(1)">text</a>'],
        ['namespace content', '<svg><foreignObject><div onmouseover="alert(1)">rich</div></foreignObject></svg><math><mtext><img src="/image" onerror="alert(1)"></mtext></math>'],
        ['forms and templates', '<form><input autofocus onfocus="alert(1)"></form><template><img src="/image" onerror="alert(1)"></template>rich'],
        ['embedded documents', '<iframe srcdoc="<script>alert(1)</script>"></iframe><object data="javascript:alert(1)"></object><embed src="/frame">rich'],
        ['escaped markup', '<div>&lt;img src="/image" onerror="alert(1)"&gt;</div>'],
        ['style content', '<span style="color:red;background-image:url(javascript:alert(1));width:expression(alert(1))">rich</span>'],
        ['quoted attributes', '<a href="https://example.invalid/" title="&quot; onmouseover=&quot;alert(1)">rich</a>'],
    ])('should retain sanitization through the actual selection fallback: %s', async (_name, html) => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        let copiedContainer: Element | undefined;
        vi.mocked(document.execCommand).mockImplementation(() => {
            const container = document.body.lastElementChild;
            if (container instanceof HTMLDivElement) {
                copiedContainer = container.cloneNode(true) as Element;
            }
            return true;
        });

        await service.write('plain', html);

        expect(copiedContainer).toBeDefined();
        expect(copiedContainer!.querySelector('script,iframe,object,embed,form,input,template,style,link,meta,svg,math')).toBeNull();
        for (const element of Array.from(copiedContainer!.querySelectorAll('*'))) {
            for (const attribute of Array.from(element.attributes)) {
                expect(attribute.name.startsWith('on')).toBe(false);
                if (attribute.name === 'href' || attribute.name === 'src') {
                    expect(attribute.value).not.toMatch(/javascript:|vbscript:/i);
                }
                if (attribute.name === 'style') {
                    expect(attribute.value).not.toMatch(/url\s*\(|expression\s*\(/i);
                }
            }
        }
        expect(document.body.childElementCount).toBe(0);
    });

    it('should preserve the fixed Excel metadata and table in the selection fallback', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        let copiedHtml = '';
        vi.mocked(document.execCommand).mockImplementation(() => {
            copiedHtml = document.body.lastElementChild?.innerHTML ?? '';
            return true;
        });

        await service.write('merged', '<html xmlns:x="urn:schemas-microsoft-com:office:excel"><head><meta name="ProgId" content="Excel.Sheet"><meta name="Generator" content="Univer"><meta http-equiv="refresh" content="0;url=https://example.invalid/"></head><body><table data-copy-id="safe"><tr><td rowspan="3" onclick="alert(1)">merged</td></tr></table></body></html>');

        expect(copiedHtml).toBe('<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta name="ProgId" content="Excel.Sheet"><meta name="Generator" content="Univer"><!--StartFragment--><table data-copy-id="safe"><tbody><tr><td rowspan="3">merged</td></tr></tbody></table><!--EndFragment-->');
        expect(document.body.childElementCount).toBe(0);
    });

    it('should restore focus and remove the fallback and copy listener when native copy throws', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();
        const input = document.createElement('input');
        document.body.appendChild(input);
        input.focus();
        vi.mocked(document.execCommand).mockImplementationOnce(() => true).mockImplementationOnce(() => {
            throw new Error('native copy failed');
        });

        await expect(service.write('rich', '<b>rich</b>')).rejects.toThrow('native copy failed');

        expect(document.body.children).toHaveLength(1);
        expect(document.activeElement).toBe(input);
        const clipboardData = { setData: vi.fn() };
        const event = new Event('copy', { cancelable: true });
        Object.defineProperty(event, 'clipboardData', { value: clipboardData });
        document.dispatchEvent(event);
        expect(clipboardData.setData).not.toHaveBeenCalled();
    });

    it('should show notification when write/writeText fails', async () => {
        const { service, logService, notificationService } = createService();
        vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(new Error('writeText failed'));
        vi.mocked(navigator.clipboard.write).mockRejectedValueOnce(new Error('write failed'));

        await service.writeText('failed');
        await service.write('failed', '<b>failed</b>');

        expect(logService.error).toHaveBeenCalledTimes(2);
        expect(notificationService.show).toHaveBeenCalledWith({
            type: 'warning',
            title: 'ui.clipboard.authentication.title',
            content: 'ui.clipboard.authentication.content',
        });
    });

    it('should throw for read/readText when clipboard api is unsupported', async () => {
        vi.mocked(supportClipboardAPI).mockReturnValue(false);
        const { service } = createService();

        await expect(service.read()).rejects.toThrow('[BrowserClipboardService] read() is not supported on this platform.');
        await expect(service.readText()).rejects.toThrow('[BrowserClipboardService] read() is not supported on this platform.');
    });

    it('should read clipboard data when supported', async () => {
        const { service } = createService();

        await expect(service.read()).resolves.toEqual([]);
        await expect(service.readText()).resolves.toBe('clipboard-text');
    });

    it('should return fallback values and notify when read/readText fails', async () => {
        const { service, logService, notificationService } = createService();
        vi.mocked(navigator.clipboard.read).mockImplementationOnce(() => {
            throw new Error('read failed');
        });
        vi.mocked(navigator.clipboard.readText).mockRejectedValueOnce(new Error('readText failed'));

        await expect(service.read()).resolves.toEqual([]);
        await expect(service.readText()).resolves.toBe('');
        expect(logService.error).toHaveBeenCalledTimes(2);
        expect(notificationService.show).toHaveBeenCalled();
    });
});
