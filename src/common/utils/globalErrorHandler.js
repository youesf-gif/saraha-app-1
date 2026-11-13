export function globalErrorHandler(error, req, res, next) {
    res.status(404).json({ message: error.message });
}

