#[derive(Clone, Copy)]
pub(crate) enum StubPhase {
    None,
    LoadingPayload,
    ImportResolving
}
