package com.ghostdeveloper.spdecode.admin

internal data class AdminPlan(val path: String, val method: String, val maxResponse: Int)

internal object NativeAdminRoutes {
    init {
        System.loadLibrary("spdecode_admin")
    }

    private external fun planNative(
        op: ByteArray,
        query: ByteArray,
        page: Int,
        bodySize: Int,
    ): Array<String>?

    fun plan(operation: String, query: String = "", page: Int = 0, bodySize: Int = 0): AdminPlan {
        if (operation == "users") require(query.length <= 80)
        val result =
            planNative(
                operation.toByteArray(Charsets.UTF_8),
                query.toByteArray(Charsets.UTF_8),
                page,
                bodySize,
            ) ?: throw IllegalArgumentException("INVALID_ADMIN_OPERATION")
        require(result.size == 3)
        return AdminPlan(result[0], result[1], result[2].toInt())
    }
}
