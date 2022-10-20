/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmark.helpers;
import org.checkerframework.checker.tainting.qual.PolyTainted;

public class Thing1 implements ThingInterface {

    @Override
    public @PolyTainted String doSomething(@PolyTainted String i) {
        // just assign input to return value
        @PolyTainted String r = i;
        return r;
    }
}
