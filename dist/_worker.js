import {handleRequest, errorToResponse, HTTPError} from "./jsonbin.js";

export default {
	async fetch(request, env) {
		if (!env.APIKEYSECRET) {
		throw new HTTPError(
			"APIKEYSECRETNotFound",
			"Not Found APIKEYSECRET Bind",
			500,
			"Internal Server Error"
		);
	        }
	
	
		try {
			const response = await handleRequest(request, env);
			return response;
		} catch (e) {
			return errorToResponse(e);
		}
	},
};
