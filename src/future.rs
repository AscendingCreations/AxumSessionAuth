use futures_util::ready;
use http::Response;
use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

// This is a Future which is Ran at the end of a Route to Process whats left over
// or add cookies ETC to the Headers or Update HTML.
pin_project! {
    /// Response future for [`SessionManager`].
    #[derive(Debug)]
    pub struct ResponseFuture<F> {
        #[pin]
        pub(crate) future: F
    }
}

/// This Portion runs when the Route has finished running.
/// It can not See any Extensions for some reason...
impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = ready!(this.future.poll(cx)?);

        Poll::Ready(Ok(res))
    }
}
