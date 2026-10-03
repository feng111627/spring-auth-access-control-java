package com.github.feng111627.springauthaccesscontroljava.http;

import com.github.feng111627.springauthaccesscontroljava.error.ApiError;
import com.github.feng111627.springauthaccesscontroljava.error.ApiException;
import com.github.feng111627.springauthaccesscontroljava.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 把异常翻译成统一错误响应 {code,message,details}，
 * HTTP 状态码与错误码一一对应，客户端可据 code 精确区分失败原因。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApi(ApiException ex) {
        ErrorCode code = ex.code();
        // 4xx 以可解释的业务结果记录，不打印堆栈；details（如剩余锁定秒数）原样透出
        log.info("请求被拒绝: code={}, message={}, details={}",
                code.name(), ex.getMessage(), ex.details());
        return ResponseEntity.status(code.httpStatus())
                .body(new ApiError(code.name(), ex.getMessage(),
                        ex.details().isEmpty() ? null : ex.details()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        log.info("请求体不可读: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiError(ErrorCode.INVALID_REQUEST.name(), "请求体不是合法的 JSON", null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleOther(Exception ex) {
        log.error("未预期的服务端异常", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError(ErrorCode.INTERNAL_ERROR.name(),
                        ErrorCode.INTERNAL_ERROR.defaultMessage(), null));
    }
}
