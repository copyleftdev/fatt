#![allow(unused_imports)]
#![allow(clippy::all)]
use super::*;
use wasm_bindgen::prelude::*;
#[cfg(web_sys_unstable_apis)]
#[wasm_bindgen]
extern "C" {
    # [wasm_bindgen (extends = :: js_sys :: Object , js_name = GPUQuerySet , typescript_type = "GPUQuerySet")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[doc = "The `GpuQuerySet` class."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/GPUQuerySet)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `GpuQuerySet`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub type GpuQuerySet;
    #[cfg(web_sys_unstable_apis)]
    #[cfg(feature = "GpuQueryType")]
    # [wasm_bindgen (structural , method , getter , js_class = "GPUQuerySet" , js_name = type)]
    #[doc = "Getter for the `type` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/GPUQuerySet/type)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `GpuQuerySet`, `GpuQueryType`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn type_(this: &GpuQuerySet) -> GpuQueryType;
    #[cfg(web_sys_unstable_apis)]
    # [wasm_bindgen (structural , method , getter , js_class = "GPUQuerySet" , js_name = count)]
    #[doc = "Getter for the `count` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/GPUQuerySet/count)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `GpuQuerySet`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn count(this: &GpuQuerySet) -> u32;
    #[cfg(web_sys_unstable_apis)]
    # [wasm_bindgen (structural , method , getter , js_class = "GPUQuerySet" , js_name = label)]
    #[doc = "Getter for the `label` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/GPUQuerySet/label)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `GpuQuerySet`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn label(this: &GpuQuerySet) -> ::alloc::string::String;
    #[cfg(web_sys_unstable_apis)]
    # [wasm_bindgen (structural , method , setter , js_class = "GPUQuerySet" , js_name = label)]
    #[doc = "Setter for the `label` field of this object."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/GPUQuerySet/label)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `GpuQuerySet`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn set_label(this: &GpuQuerySet, value: &str);
    #[cfg(web_sys_unstable_apis)]
    # [wasm_bindgen (method , structural , js_class = "GPUQuerySet" , js_name = destroy)]
    #[doc = "The `destroy()` method."]
    #[doc = ""]
    #[doc = "[MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/GPUQuerySet/destroy)"]
    #[doc = ""]
    #[doc = "*This API requires the following crate features to be activated: `GpuQuerySet`*"]
    #[doc = ""]
    #[doc = "*This API is unstable and requires `--cfg=web_sys_unstable_apis` to be activated, as"]
    #[doc = "[described in the `wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/web-sys/unstable-apis.html)*"]
    pub fn destroy(this: &GpuQuerySet);
}
