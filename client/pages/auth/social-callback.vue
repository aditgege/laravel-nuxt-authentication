<template>
<div class="container">
    <p>Please wait...</p>
</div>
</template>

<script>
export default {
    data() {
        return {
            token: this.$route.query.token ? this.$route.query.token : null
        }
    },
    mounted() {
        this.$auth.login({ data: {
            token: this.token
        }}).catch( (e) => {
            return this.$router.push('/auth/register?error=Your token appeared to be invalid, try again.')
        });
    }
}
</script>
