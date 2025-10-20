export async function handleRequest(request, env) {
	if (!env.JSONBIN) {
		throw new HTTPError(
			"kvNotFound",
			"Not Found KV Database Bind",
			500,
			"Internal Server Error"
		);
	}

	const APIKEY = env.APIKEYSECRET;

	// first check if the request is authorized
	const { headers } = request;
	const urlObj = new URL(request.url);
	const authorization = headers.get("Authorization");
	const headerAuthorizationValue = `Bearer ${APIKEY}`;
	if (authorization) {
		if (authorization !== headerAuthorizationValue) {
			// if not authorized, return 401
			throw new HTTPError(
				"unauthorized",
				"Authrorization Bearer abc is required",
				401,
				"Unauthorized"
			);
		}
	} else if (urlObj.searchParams.has("key")) {
		const keyFromQuery = urlObj.searchParams.get("key");
		if (keyFromQuery !== APIKEY) {
			throw new HTTPError(
				"unauthorized",
				"search query key=abc is required",
				401,
				"Unauthorized"
			);
		}
	} else {
		throw new HTTPError(
			"unauthorized",
			"Authrorization Bearer abc or search query key=abc is required",
			401,
			"Unauthorized"
		);
	}

	// redirect
	let redirect = urlObj.searchParams.has("redirect");
	let encbase64 = urlObj.searchParams.has("enc");

	// qeuery
	let qeuery = urlObj.searchParams.has("q") ? urlObj.searchParams.get("q") : undefined;

	console.log(`redirect=${redirect}, query=${qeuery}, search:${urlObj.search}, request.url:${request.url}`)
	// yes authorized, continue
	if (request.method === "POST") {
		const { pathname } = new URL(request.url);
		let json = "";
		var text = await request.text();
		if (encbase64){
			text = btoa(text);
		}
		if (qeuery) {
			json = `{\"${qeuery}\" : \"${text}\"}`;
			
		} else {
			try {
				json = JSON.stringify(await request.json());
			} catch (e) {
				throw new HTTPError(
					"jsonParseError",
					"request body JSON is not valid, " + e.message,
					400,
					"Bad Request"
				);
			}
		}
		console.log(`Update pathname: ${pathname}, json: ${json}`)
		await env.JSONBIN.put(pathname, json);
		return new Response('{"ok":true}', {
			headers: {
				"Content-Type": "application/json",
			},
		});
	} else if (request.method === "GET") {
		const { pathname } = new URL(request.url);
		const value = await env.JSONBIN.get(pathname);
		if (value === null) {
			throw new HTTPError(
				"notFound",
				"Not Found",
				404,
				"The requested resource was not found"
			);
		}
		if (redirect) {
			const value_json = await env.JSONBIN.get(pathname, { type: 'json' });

			if (!value_json || !value_json.url) {
				throw new HTTPError(
					"urlNotFound",
					"urlNotFound",
					404,
					"Not Found"
				);
			}

			const url = value_json.url;
			// Return a 302 redirect response
			return new Response(null, {
				status: 302,
				headers: {
					"Location": url,
					// Optional: for clarity
					"Cache-Control": "no-store",
				},
			});

		}


		if (qeuery) {
			const value_json = await env.JSONBIN.get(pathname, { type: 'json' });
			if (!value_json || !value_json[qeuery]) {
				throw new HTTPError(
					`${qeuery}NotFound`,
					`${qeuery}NotFound`,
					404,
					"Not Found"
				);
			}
			var text = value_json[qeuery];
		    if (encbase64){
		    	text = atob(text);
		    }
			return new Response(text, {
				headers: {
					"Content-Type": "text/html",
				},
			});

		} else {
			return new Response(value, {
				headers: {
					"Content-Type": "application/json",
				},
			});
		}

	} else {
		throw new HTTPError(
			"methodNotAllowed",
			"Method Not Allowed",
			405,
			"The requested method is not allowed"
		);
	}
}

function escape (key, val) {
    if (typeof(val)!="string") return val;
    return val      
        .replace(/[\\]/g, '\\\\')
        .replace(/[\/]/g, '\\/')
        .replace(/[\b]/g, '\\b')
        .replace(/[\f]/g, '\\f')
        .replace(/[\n]/g, '\\n')
        .replace(/[\r]/g, '\\r')
        .replace(/[\t]/g, '\\t')
        .replace(/[\"]/g, '\\"')
        .replace(/\\'/g, "\\'"); 
}

export function errorToResponse(error) {
	const bodyJson = {
		ok: false,
		error: "Internal Server Error",
		message: "Internal Server Error",
	};
	let status = 500;
	let statusText = "Internal Server Error";

	if (error instanceof Error) {
		bodyJson.message = error.message;
		bodyJson.error = error.name;

		if (error.status) {
			status = error.status;
		}
		if (error.statusText) {
			statusText = error.statusText;
		}
	}
	return new Response(JSON.stringify(bodyJson, null, 2), {
		status: status,
		statusText: statusText,
		headers: {
			"Content-Type": "application/json",
		},
	});
}

export class HTTPError extends Error {
	constructor(name, message, status, statusText) {
		super(message);
		this.name = name;
		this.status = status;
		this.statusText = statusText;
	}
}