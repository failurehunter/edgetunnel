// @ts-nocheck
// Фаза 3, Шаг 3.2: обфускационные токены — перенос «как есть» из монолита.
// Назначение — review/аудит: словарь преобразует имена объектов JS в
// строковые маски (Proxy.name → "PROXYIP", URL.name → ...) и UA-строку
// для подписок. Используется в decoy-страницах, коннекторах и SUB API.
// Не развивать без согласования с реестром 1.1.

export const 特征码字典 = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];

export const 汇聚订阅_UA = 'v2rayN/edge' + 'tunnel (https://github.com/' + 特征码字典[1] + '/edge' + 'tunnel)';